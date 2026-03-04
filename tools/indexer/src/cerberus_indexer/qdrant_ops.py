"""
Qdrant collection management, point building, and deletion helpers.

This module owns all direct interactions with the Qdrant client that are
shared between the indexer pipeline and the MCP server:

- Collection creation / migration (dense + sparse vector configs)
- Building ``PointStruct`` objects from code chunks and patterns
- Deletion of points by file path or by explicit IDs
"""

from __future__ import annotations

import logging
from typing import List, Optional

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from cerberus_indexer.chunking import deterministic_id
from cerberus_indexer.config import (
    COLLECTION_NAME,
    DENSE_VECTOR_NAME,
    METADATA_PATH,
    SPARSE_VECTOR_NAME,
)
from cerberus_indexer.embeddings import HybridEmbedding
from cerberus_indexer.models import CodeChunk, Evidence, PatternEntry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Collection lifecycle
# ---------------------------------------------------------------------------


def ensure_collection(
    client: QdrantClient,
    dense_vector_size: int,
    collection_name: str = COLLECTION_NAME,
    recreate: bool = False,
) -> None:
    """
    Ensure that *collection_name* exists with both dense and sparse
    vector configurations.

    Behaviour
    ---------
    - If *recreate* is ``True`` and the collection already exists it is
      deleted first.
    - If the collection does not exist it is created from scratch with
      the correct dense + sparse vector layout.
    - If the collection exists but lacks the sparse vector config (e.g.
      it was created by the upstream ``mcp-server-qdrant``), the sparse
      config is added via ``update_collection`` (auto-migration).
    - After collection creation/verification, payload indexes are created
      on filterable fields via :func:`ensure_payload_indexes`.

    Parameters
    ----------
    client:
        Connected Qdrant client.
    dense_vector_size:
        Dimensionality of the dense embedding model (e.g. 384 for MiniLM).
    collection_name:
        Target collection.
    recreate:
        If ``True``, drop and recreate the collection.
    """
    if recreate and client.collection_exists(collection_name):
        logger.info("Deleting existing collection '%s' (--recreate)", collection_name)
        client.delete_collection(collection_name)

    if not client.collection_exists(collection_name):
        client.create_collection(
            collection_name=collection_name,
            vectors_config={
                DENSE_VECTOR_NAME: qmodels.VectorParams(
                    size=dense_vector_size,
                    distance=qmodels.Distance.COSINE,
                ),
            },
            sparse_vectors_config={
                SPARSE_VECTOR_NAME: qmodels.SparseVectorParams(
                    index=qmodels.SparseIndexParams(on_disk=False),
                ),
            },
        )
        logger.info(
            "Created collection '%s' — dense: '%s' (dim=%d, cosine), sparse: '%s' (BM25)",
            collection_name,
            DENSE_VECTOR_NAME,
            dense_vector_size,
            SPARSE_VECTOR_NAME,
        )
    else:
        # Collection exists — verify it has the sparse vector config.
        info = client.get_collection(collection_name)
        existing_sparse: set[str] = set()
        if info.config.params.sparse_vectors:
            existing_sparse = set(info.config.params.sparse_vectors.keys())

        if SPARSE_VECTOR_NAME not in existing_sparse:
            logger.info(
                "Adding sparse vector '%s' to existing collection '%s'…",
                SPARSE_VECTOR_NAME,
                collection_name,
            )
            client.update_collection(
                collection_name=collection_name,
                sparse_vectors_config={
                    SPARSE_VECTOR_NAME: qmodels.SparseVectorParams(
                        index=qmodels.SparseIndexParams(on_disk=False),
                    ),
                },
            )
            logger.info("Sparse vector '%s' added successfully.", SPARSE_VECTOR_NAME)
        else:
            logger.info("Collection '%s' already configured for hybrid search.", collection_name)

    ensure_payload_indexes(client, collection_name)


# ---------------------------------------------------------------------------
# Payload indexes
# ---------------------------------------------------------------------------


def ensure_payload_indexes(
    client: QdrantClient,
    collection_name: str = COLLECTION_NAME,
) -> None:
    """
    Create Qdrant payload indexes on filterable fields for v0.3.0.

    Idempotent — safe to call on an existing collection.  Indexes that
    already exist are silently skipped by Qdrant.
    """
    keyword_fields = [
        f"{METADATA_PATH}.subsystem",
        f"{METADATA_PATH}.crate",
        f"{METADATA_PATH}.kind",
        f"{METADATA_PATH}.symbols",
        f"{METADATA_PATH}.declared",
        f"{METADATA_PATH}.calls",
        "type",
    ]
    bool_fields = [
        f"{METADATA_PATH}.is_test",
    ]

    for field_name in keyword_fields:
        try:
            client.create_payload_index(
                collection_name=collection_name,
                field_name=field_name,
                field_schema=qmodels.PayloadSchemaType.KEYWORD,
            )
            logger.debug("Created keyword payload index on '%s'.", field_name)
        except Exception:
            # Index already exists or collection doesn't support it — ignore.
            pass

    for field_name in bool_fields:
        try:
            client.create_payload_index(
                collection_name=collection_name,
                field_name=field_name,
                field_schema=qmodels.PayloadSchemaType.BOOL,
            )
            logger.debug("Created bool payload index on '%s'.", field_name)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Point builders
# ---------------------------------------------------------------------------


def _evidence_to_dict(ev: Evidence) -> dict:
    """Serialise an :class:`Evidence` to a JSON-safe dict for the payload."""
    return {
        "file_path": ev.file_path,
        "line_start": ev.line_start,
        "line_end": ev.line_end,
        "code_snippet": ev.code_snippet,
        "context": ev.context,
    }


def build_code_points(
    chunks: List[CodeChunk],
    embeddings: List[HybridEmbedding],
) -> List[qmodels.PointStruct]:
    """
    Build Qdrant points from code chunks and their hybrid embeddings.

    Each point carries:
    - Two named vectors (dense + sparse).
    - A payload with ``type: "code_chunk"``, the document text, and
      structured ``metadata`` including v0.3.0 fields (symbols, kind,
      subsystem, crate, module_path, is_test, is_unsafe, calls, etc.).

    The point ID is deterministic (namespace ``"code"`` + file + chunk index)
    so upserts are idempotent.
    """
    points: List[qmodels.PointStruct] = []
    for chunk, emb in zip(chunks, embeddings):
        pid = deterministic_id("code", f"{chunk.file}::{chunk.chunk_index}")
        points.append(
            qmodels.PointStruct(
                id=pid,
                vector={
                    DENSE_VECTOR_NAME: emb.dense.values,
                    SPARSE_VECTOR_NAME: emb.sparse.to_qdrant(),
                },
                payload={
                    "type": "code_chunk",
                    "document": chunk.text,
                    METADATA_PATH: {
                        "file": chunk.file,
                        "chunk_index": chunk.chunk_index,
                        "total_chunks": chunk.total_chunks,
                        "language": chunk.language,
                        "hash": chunk.hash,
                        # v0.3.0
                        "line_start": chunk.line_start,
                        "line_end": chunk.line_end,
                        "symbols": chunk.symbols,
                        "declared": chunk.declared,
                        "kind": chunk.kind,
                        "crate": chunk.crate_name,
                        "subsystem": chunk.subsystem,
                        "module_path": chunk.module_path,
                        "is_test": chunk.is_test,
                        "is_unsafe": chunk.is_unsafe,
                        "calls": chunk.calls,
                        "doc_comment": chunk.doc_comment,
                    },
                },
            )
        )
    return points


def build_pattern_points(
    patterns: List[PatternEntry],
    embeddings: List[HybridEmbedding],
) -> List[qmodels.PointStruct]:
    """
    Build Qdrant points from pattern entries and their hybrid embeddings.

    Each point carries:
    - Two named vectors (dense + sparse).
    - A payload with ``type: "pattern"`` and structured pattern metadata
      (name, reason, tags, evidence list, etc.).

    The point ID is the deterministic ``pattern_id`` computed during
    mining, so upserts are idempotent.
    """
    points: List[qmodels.PointStruct] = []
    for entry, emb in zip(patterns, embeddings):
        points.append(
            qmodels.PointStruct(
                id=entry.pattern_id,
                vector={
                    DENSE_VECTOR_NAME: emb.dense.values,
                    SPARSE_VECTOR_NAME: emb.sparse.to_qdrant(),
                },
                payload={
                    "type": "pattern",
                    "pattern_name": entry.pattern_name,
                    "origin_path": entry.origin_path,
                    "snippet": entry.snippet,
                    "reason": entry.reason,
                    "tags": entry.tags,
                    "scope_paths": entry.scope_paths,
                    "evidence": [_evidence_to_dict(ev) for ev in entry.evidence],
                    "timestamp": entry.timestamp,
                    "confidence": entry.confidence,
                },
            )
        )
    return points


def build_store_point(
    information: str,
    emb: HybridEmbedding,
    metadata: Optional[dict] = None,
) -> qmodels.PointStruct:
    """
    Build a single point for the MCP ``qdrant-store`` tool.

    Uses the same named-vector layout as the indexer so that all points
    in a collection are hybrid-searchable.  The point ID is derived
    deterministically from the *information* text so that storing the
    same text twice overwrites rather than duplicates.
    """
    pid = deterministic_id("mcp-store", information)
    return qmodels.PointStruct(
        id=pid,
        vector={
            DENSE_VECTOR_NAME: emb.dense.values,
            SPARSE_VECTOR_NAME: emb.sparse.to_qdrant(),
        },
        payload={
            "type": "mcp_stored",
            "document": information,
            METADATA_PATH: metadata,
        },
    )


# ---------------------------------------------------------------------------
# Deletion helpers
# ---------------------------------------------------------------------------


def delete_code_points_for_file(
    client: QdrantClient,
    file_path: str,
    collection_name: str = COLLECTION_NAME,
) -> None:
    """Delete all ``code_chunk`` points whose ``metadata.file`` matches *file_path*."""
    client.delete(
        collection_name=collection_name,
        points_selector=qmodels.FilterSelector(
            filter=qmodels.Filter(
                must=[
                    qmodels.FieldCondition(
                        key=f"{METADATA_PATH}.file",
                        match=qmodels.MatchValue(value=file_path),
                    ),
                    qmodels.FieldCondition(
                        key="type",
                        match=qmodels.MatchValue(value="code_chunk"),
                    ),
                ]
            )
        ),
    )


def delete_points_by_ids(
    client: QdrantClient,
    ids: List[str],
    collection_name: str = COLLECTION_NAME,
) -> None:
    """Delete points by their explicit IDs.  No-op if *ids* is empty."""
    if not ids:
        return
    client.delete(
        collection_name=collection_name,
        points_selector=qmodels.PointIdsList(points=ids),
    )
