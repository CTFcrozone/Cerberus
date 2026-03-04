"""
Main indexing pipeline for the CrucibleOS codebase.

Orchestrates the full index-or-update cycle:

1. Walk the repository for in-scope source files.
2. Compute content hashes to detect changed / removed files.
3. Generate hybrid (dense + sparse) embeddings for new / changed chunks.
4. Upsert code-chunk points into Qdrant.
5. Mine architecture patterns and upsert pattern points.
6. Persist incremental state so the next run can skip unchanged files.

Performance architecture (v0.2.0)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The code-chunk sub-pipeline uses a **3-stage concurrent pipeline** to
overlap CPU-bound embedding with network I/O:

    ┌──────────────┐   embed_q   ┌──────────────┐   upsert_q   ┌──────────────┐
    │  Producer     │ ──────────→ │  Embedder     │ ───────────→ │  Upserter    │
    │  (thread)     │             │  (main thread) │             │  (thread(s)) │
    │               │             │               │             │               │
    │ walk / hash / │             │ ONNX Runtime  │             │ Qdrant HTTP   │
    │ chunk / delete│             │ dense+sparse  │             │ batch upsert  │
    └──────────────┘             └──────────────┘             └──────────────┘

Chunks are accumulated across multiple files into **coarse batches**
(default 256 texts) before being sent to the embedding model, which
dramatically improves ONNX Runtime throughput on both GPU and CPU.

This module is consumed by :mod:`cerberus_indexer.cli` (the ``cerberus-index``
entry point).  It is intentionally synchronous from the caller's
perspective — all concurrency is internal.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from qdrant_client import QdrantClient

from cerberus_indexer.chunking import (
    batched,
    collect_code_chunks,
    file_hash,
    should_index_code,
)
from cerberus_indexer.config import (
    BATCH_SIZE,
    CHUNK_OVERLAP,
    CHUNK_WORDS,
    COLLECTION_NAME,
    EMBED_BATCH_SIZE,
    PIPELINE_QUEUE_DEPTH,
    QDRANT_API_KEY,
    QDRANT_URL,
    STATE_PATH_DEFAULT,
    UPSERT_WORKERS,
)
from cerberus_indexer.embeddings import EmbeddingManager
from cerberus_indexer.models import CodeChunk
from cerberus_indexer.patterns import mine_patterns
from cerberus_indexer.qdrant_ops import (
    build_code_points,
    build_pattern_points,
    delete_code_points_for_file,
    delete_points_by_ids,
    ensure_collection,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pipeline data structures
# ---------------------------------------------------------------------------


@dataclass
class _EmbedBatch:
    """
    A batch of chunks from one or more files, ready for embedding.

    Carried on the ``embed_queue`` between the producer and the
    embedder (main thread).
    """

    chunks: List[CodeChunk]
    file_hashes: Dict[str, str] = field(default_factory=dict)


@dataclass
class _UpsertBatch:
    """
    Embedded points ready for Qdrant upsert.

    Carried on the ``upsert_queue`` between the embedder (main thread)
    and the upserter thread(s).
    """

    from qdrant_client.http import models as _qm

    points: List[_qm.PointStruct]
    file_hashes: Dict[str, str] = field(default_factory=dict)


# Sentinel value placed on queues to signal "no more work".
_SENTINEL = None


@dataclass
class _PipelineStats:
    """Mutable counters shared (safely) between pipeline stages."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    total_chunks: int = 0
    skipped_files: int = 0
    upserted_points: int = 0
    producer_errors: int = 0
    embedder_errors: int = 0
    upserter_errors: int = 0

    # Timing (seconds, monotonic)
    producer_wall: float = 0.0
    embedder_wall: float = 0.0
    upserter_wall: float = 0.0


# ---------------------------------------------------------------------------
# Incremental state persistence
# ---------------------------------------------------------------------------


def load_state(path: Path) -> Dict[str, Dict[str, str]]:
    """
    Load incremental indexing state from *path*.

    Returns a dict with two sub-dicts:

    - ``"files"``:    ``{relative_path: blake2s_hex}``
    - ``"patterns"``: ``{pattern_id: "present"}``

    If the file does not exist or is corrupt an empty state is returned.
    """
    if not path.exists():
        return {"files": {}, "patterns": {}}
    try:
        with path.open("r", encoding="utf-8") as f:
            state = json.load(f)
            state.setdefault("files", {})
            state.setdefault("patterns", {})
            return state
    except Exception:
        return {"files": {}, "patterns": {}}


def save_state(path: Path, state: Dict[str, Dict[str, str]]) -> None:
    """Persist incremental indexing state to *path*."""
    with path.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


# ---------------------------------------------------------------------------
# Public pipeline entry point
# ---------------------------------------------------------------------------


def run_index(
    repo_root: Path,
    *,
    recreate: bool = False,
    skip_code: bool = False,
    skip_patterns: bool = False,
    state_path: str = STATE_PATH_DEFAULT,
    collection_name: str = COLLECTION_NAME,
    chunk_words: int = CHUNK_WORDS,
    chunk_overlap: int = CHUNK_OVERLAP,
    batch_size: int = BATCH_SIZE,
    embed_batch_size: int = EMBED_BATCH_SIZE,
    upsert_workers: int = UPSERT_WORKERS,
    backend: Optional[str] = None,
    dense_model: Optional[str] = None,
) -> None:
    """
    Run the full indexing pipeline against *repo_root*.

    Parameters
    ----------
    repo_root:
        Absolute path to the CrucibleOS repository root.
    recreate:
        If ``True``, delete and recreate the Qdrant collection.
    skip_code:
        If ``True``, skip code-chunk indexing.
    skip_patterns:
        If ``True``, skip pattern mining and upsert.
    state_path:
        Repo-relative path to the incremental state JSON file.
    collection_name:
        Name of the Qdrant collection to index into.
    chunk_words:
        Number of words per code chunk.
    chunk_overlap:
        Word overlap between consecutive chunks.
    batch_size:
        Number of points per Qdrant upsert batch.
    embed_batch_size:
        Number of text chunks to accumulate before sending a single
        batch to the embedding model.  Larger → better GPU throughput.
    upsert_workers:
        Number of threads dedicated to Qdrant upsert I/O.
    backend:
        Dense embedding backend (``"fastembed"`` or
        ``"sentence-transformers"``).  ``None`` uses the config default.
    dense_model:
        HuggingFace model identifier for the dense encoder.  ``None``
        uses the config default.
    """
    t0 = time.monotonic()
    repo_root = repo_root.resolve()
    abs_state_path = repo_root / state_path

    logger.info("Qdrant URL       : %s", QDRANT_URL)
    logger.info("Collection       : %s", collection_name)
    logger.info("Repo root        : %s", repo_root)
    logger.info("Embed batch size : %d", embed_batch_size)
    logger.info("Upsert workers   : %d", upsert_workers)

    # -- Qdrant client -------------------------------------------------------
    client = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY)

    # -- Embedding models ----------------------------------------------------
    logger.info("[model] Loading dense + sparse embedding models…")
    emb_kwargs = {}
    if backend is not None:
        emb_kwargs["backend"] = backend
    if dense_model is not None:
        emb_kwargs["dense_model_name"] = dense_model
    emb = EmbeddingManager(**emb_kwargs)
    # dense_dim triggers lazy model load → ONNX provider probing happens here.
    dense_dim = emb.dense_dim
    logger.info("[model] Dense vector dimension: %d", dense_dim)
    # Now active_provider reflects what ONNX Runtime *actually* loaded
    # (not what was requested), so this log line is trustworthy.
    if emb.is_gpu:
        logger.info("[model] 🚀 GPU acceleration ACTIVE (%s)", emb.active_provider)
    else:
        logger.info("[model] CPU inference (%s)", emb.active_provider)

    # -- Collection setup ----------------------------------------------------
    ensure_collection(
        client,
        dense_vector_size=dense_dim,
        collection_name=collection_name,
        recreate=recreate,
    )

    # -- Incremental state ---------------------------------------------------
    if recreate:
        # Wipe the state file so every file is re-hashed, re-chunked,
        # and re-embedded — matching the fact that we just nuked the
        # Qdrant collection.
        state: Dict[str, Dict[str, str]] = {"files": {}, "patterns": {}}
        save_state(abs_state_path, state)
        logger.info("State file reset (--recreate): %s", abs_state_path)
    else:
        state = load_state(abs_state_path)
        logger.info("State file       : %s", abs_state_path)

    # -----------------------------------------------------------------------
    # Code indexing
    # -----------------------------------------------------------------------
    if not skip_code:
        _index_code(
            client=client,
            emb=emb,
            repo_root=repo_root,
            state=state,
            collection_name=collection_name,
            chunk_words=chunk_words,
            chunk_overlap=chunk_overlap,
            batch_size=batch_size,
            embed_batch_size=embed_batch_size,
            upsert_workers=upsert_workers,
        )

    # -----------------------------------------------------------------------
    # Pattern indexing
    # -----------------------------------------------------------------------
    if not skip_patterns:
        _index_patterns(
            client=client,
            emb=emb,
            repo_root=repo_root,
            state=state,
            collection_name=collection_name,
            batch_size=batch_size,
        )

    # -- Persist state -------------------------------------------------------
    save_state(abs_state_path, state)
    elapsed = time.monotonic() - t0
    logger.info("State saved to %s", abs_state_path)
    print(f"✅ Indexing complete in {elapsed:.1f}s. Collection is ready for hybrid MCP queries.")


# ---------------------------------------------------------------------------
# 3-stage pipeline: code-chunk sub-pipeline
# ---------------------------------------------------------------------------


def _index_code(
    *,
    client: QdrantClient,
    emb: EmbeddingManager,
    repo_root: Path,
    state: Dict[str, Dict[str, str]],
    collection_name: str,
    chunk_words: int,
    chunk_overlap: int,
    batch_size: int,
    embed_batch_size: int,
    upsert_workers: int,
) -> None:
    """
    Incrementally index code chunks using a 3-stage concurrent pipeline.

    Stage A — **Producer** (background thread):
        Walks the repo, hashes files, skips unchanged ones, deletes
        stale Qdrant points for changed files, chunks the source text,
        and accumulates chunks into coarse embedding batches.

    Stage B — **Embedder** (main thread):
        Pulls batches from the producer, runs the dense + sparse
        embedding models (CPU- or GPU-bound), builds Qdrant points,
        and pushes them to the upsert queue.

    Stage C — **Upserter** (background thread(s)):
        Pulls point batches from the embedder and upserts them to
        Qdrant via HTTP.  Multiple workers can be used for high-
        latency remote servers.

    Thread-safety of ``state``
    ~~~~~~~~~~~~~~~~~~~~~~~~~~
    The producer *reads* ``state["files"]`` to decide whether a file
    changed.  The upserter *writes* ``state["files"][path] = hash``
    after a successful upsert.  There is no race because a file's hash
    is only read **before** its chunks enter the pipeline and only
    written **after** they exit.  Python's GIL guarantees dict get/set
    atomicity for simple keys.
    """
    t_start = time.monotonic()

    # -- Pre-pass: delete points for files removed since last run -----------
    files_to_index: List[Path] = []
    current_files: Set[str] = set()

    for path in sorted(repo_root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(repo_root)
        except ValueError:
            continue
        if not should_index_code(rel):
            continue
        files_to_index.append(rel)
        current_files.add(rel.as_posix())

    removed_files = set(state["files"].keys()) - current_files
    for removed in removed_files:
        logger.info("[code] Deleting removed file points: %s", removed)
        delete_code_points_for_file(client, removed, collection_name)
        state["files"].pop(removed, None)

    if removed_files:
        logger.info("[code] Cleaned up %d removed file(s).", len(removed_files))

    # -- Pipeline queues -----------------------------------------------------
    embed_q: queue.Queue[Optional[_EmbedBatch]] = queue.Queue(
        maxsize=PIPELINE_QUEUE_DEPTH,
    )
    upsert_q: queue.Queue[Optional[_UpsertBatch]] = queue.Queue(
        maxsize=PIPELINE_QUEUE_DEPTH * 2,
    )

    stats = _PipelineStats()

    # -- Stage A: Producer thread -------------------------------------------

    def _producer() -> None:
        """Walk → hash → chunk → accumulate → enqueue embed batches."""
        t0 = time.monotonic()
        chunk_buffer: List[CodeChunk] = []
        hash_buffer: Dict[str, str] = {}

        try:
            for rel in files_to_index:
                abs_path = repo_root / rel
                rel_str = rel.as_posix()

                try:
                    h = file_hash(abs_path)
                except Exception as exc:
                    logger.warning("[producer] Failed to hash %s: %s", rel_str, exc)
                    with stats.lock:
                        stats.producer_errors += 1
                    continue

                if state["files"].get(rel_str) == h:
                    with stats.lock:
                        stats.skipped_files += 1
                    continue

                # File changed — delete stale Qdrant points.
                # This is a network call but runs in the producer thread,
                # overlapping with whatever the embedder is doing.
                try:
                    delete_code_points_for_file(client, rel_str, collection_name)
                except Exception as exc:
                    logger.warning(
                        "[producer] Failed to delete stale points for %s: %s",
                        rel_str,
                        exc,
                    )
                    # Continue — the upsert is idempotent and will
                    # overwrite stale points via deterministic IDs.

                try:
                    chunks = collect_code_chunks(
                        abs_path,
                        rel_str,
                        chunk_words,
                        chunk_overlap,
                    )
                except Exception as exc:
                    logger.warning("[producer] Failed to chunk %s: %s", rel_str, exc)
                    with stats.lock:
                        stats.producer_errors += 1
                    continue

                if not chunks:
                    # File too short to chunk — still mark as indexed so
                    # we don't re-process it next time.
                    hash_buffer[rel_str] = h
                    continue

                chunk_buffer.extend(chunks)
                hash_buffer[rel_str] = h

                # Flush when we've accumulated enough for a coarse batch.
                if len(chunk_buffer) >= embed_batch_size:
                    embed_q.put(
                        _EmbedBatch(
                            chunks=chunk_buffer,
                            file_hashes=hash_buffer,
                        )
                    )
                    chunk_buffer = []
                    hash_buffer = {}

            # Flush remaining chunks (partial batch).
            if chunk_buffer:
                embed_q.put(
                    _EmbedBatch(
                        chunks=chunk_buffer,
                        file_hashes=hash_buffer,
                    )
                )
            # Flush empty-file hashes (files too short to produce chunks
            # but whose hash should still be recorded in state).
            elif hash_buffer:
                embed_q.put(_EmbedBatch(chunks=[], file_hashes=hash_buffer))
        except Exception:
            logger.exception("[producer] Unexpected error in producer thread")
        finally:
            embed_q.put(_SENTINEL)
            stats.producer_wall = time.monotonic() - t0

    # -- Stage C: Upserter thread(s) ----------------------------------------

    def _upserter() -> None:
        """Pull _UpsertBatch from the queue and upsert to Qdrant."""
        t0 = time.monotonic()
        while True:
            item = upsert_q.get()
            if item is _SENTINEL:
                upsert_q.task_done()
                break

            batch: _UpsertBatch = item
            try:
                for sub in batched(batch.points, batch_size):
                    client.upsert(collection_name=collection_name, points=sub)

                with stats.lock:
                    stats.upserted_points += len(batch.points)

                # Mark files as indexed **after** successful upsert.
                for rel_str, h in batch.file_hashes.items():
                    state["files"][rel_str] = h

            except Exception as exc:
                logger.error("[upserter] Upsert failed: %s", exc)
                with stats.lock:
                    stats.upserter_errors += 1
            finally:
                upsert_q.task_done()

        stats.upserter_wall = time.monotonic() - t0

    # -- Launch threads ------------------------------------------------------

    producer_thread = threading.Thread(
        target=_producer,
        name="indexer-producer",
        daemon=True,
    )

    upserter_threads: List[threading.Thread] = []
    for i in range(upsert_workers):
        t = threading.Thread(
            target=_upserter,
            name=f"indexer-upserter-{i}",
            daemon=True,
        )
        upserter_threads.append(t)

    producer_thread.start()
    for t in upserter_threads:
        t.start()

    # -- Stage B: Embedder (main thread) ------------------------------------

    t_embed_start = time.monotonic()
    embed_batches_processed = 0

    while True:
        item = embed_q.get()
        if item is _SENTINEL:
            break

        eb: _EmbedBatch = item

        if not eb.chunks:
            # Empty batch — just forward file hashes (files too small
            # to produce chunks but whose state should still be updated).
            upsert_q.put(_UpsertBatch(points=[], file_hashes=eb.file_hashes))
            continue

        try:
            texts = [c.text for c in eb.chunks]
            embeddings = emb.embed_passages(texts)
            points = build_code_points(eb.chunks, embeddings)

            upsert_q.put(_UpsertBatch(points=points, file_hashes=eb.file_hashes))

            with stats.lock:
                stats.total_chunks += len(eb.chunks)

            embed_batches_processed += 1
            logger.info(
                "[embedder] Batch %d: %d chunks → %d points",
                embed_batches_processed,
                len(eb.chunks),
                len(points),
            )

        except Exception as exc:
            logger.error("[embedder] Embedding failed for batch: %s", exc)
            with stats.lock:
                stats.embedder_errors += 1

    stats.embedder_wall = time.monotonic() - t_embed_start

    # -- Signal upsert workers to drain and stop ----------------------------
    for _ in upserter_threads:
        upsert_q.put(_SENTINEL)

    # -- Wait for all threads -----------------------------------------------
    producer_thread.join()
    for t in upserter_threads:
        t.join()

    # -- Report --------------------------------------------------------------
    elapsed = time.monotonic() - t_start

    logger.info(
        "[code] Pipeline complete in %.1fs (producer=%.1fs, embedder=%.1fs, upserter=%.1fs)",
        elapsed,
        stats.producer_wall,
        stats.embedder_wall,
        stats.upserter_wall,
    )
    logger.info(
        "[code] Chunks: %d upserted, %d files skipped (unchanged), "
        "%d errors (producer=%d, embedder=%d, upserter=%d)",
        stats.total_chunks,
        stats.skipped_files,
        stats.producer_errors + stats.embedder_errors + stats.upserter_errors,
        stats.producer_errors,
        stats.embedder_errors,
        stats.upserter_errors,
    )
    print(
        f"[code] {stats.total_chunks} chunks upserted in {elapsed:.1f}s, "
        f"{stats.skipped_files} files skipped."
    )
    if stats.producer_errors or stats.embedder_errors or stats.upserter_errors:
        print(
            f"[code] ⚠ {stats.producer_errors + stats.embedder_errors + stats.upserter_errors} "
            f"errors occurred — check logs for details."
        )


# ---------------------------------------------------------------------------
# Pattern sub-pipeline (not pipelined — batch is small)
# ---------------------------------------------------------------------------


def _index_patterns(
    *,
    client: QdrantClient,
    emb: EmbeddingManager,
    repo_root: Path,
    state: Dict[str, Dict[str, str]],
    collection_name: str,
    batch_size: int,
) -> None:
    """Mine and index architecture patterns from the repository."""
    patterns = mine_patterns(repo_root)

    if not patterns:
        logger.info("[pattern] No patterns found.")
        return

    # Build the text that will be embedded for each pattern.
    pattern_texts: List[str] = []
    for p in patterns:
        evidence_text = "\n".join(
            f"{e.file_path}:{e.line_start} {e.code_snippet}" for e in p.evidence[:5]
        )
        pattern_texts.append(
            f"{p.pattern_name}\n"
            f"Reason: {p.reason}\n"
            f"Snippet: {p.snippet}\n"
            f"Evidence:\n{evidence_text}"
        )

    embeddings = emb.embed_passages(pattern_texts)
    points = build_pattern_points(patterns, embeddings)

    for batch in batched(points, batch_size):
        client.upsert(collection_name=collection_name, points=batch)

    # Incremental deletion for patterns no longer present.
    current_pattern_ids = {p.pattern_id for p in patterns}
    stale_pattern_ids = set(state["patterns"].keys()) - current_pattern_ids
    delete_points_by_ids(client, list(stale_pattern_ids), collection_name)

    # Update pattern state.
    for pid in current_pattern_ids:
        state["patterns"][pid] = "present"
    for pid in stale_pattern_ids:
        state["patterns"].pop(pid, None)

    logger.info(
        "[pattern] Upserted %d patterns (hybrid), deleted %d stale.",
        len(points),
        len(stale_pattern_ids),
    )
    print(f"[pattern] Upserted {len(points)} patterns, deleted {len(stale_pattern_ids)} stale.")
