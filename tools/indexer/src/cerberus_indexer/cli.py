"""
CLI entry point for the Cerberus repository indexer and interactive search.

Provides the ``cerberus-index`` console command with two modes.

Performance tuning flags (``--embed-batch-size``, ``--upsert-workers``)
control the 3-stage pipeline that overlaps file I/O, embedding, and
Qdrant upserts for maximum throughput.

Modes
~~~~~
"""

Index mode (default)
    Walk the repository, chunk source files, mine patterns, embed with
    both dense (MiniLM) and sparse (BM25) models, and upsert hybrid
    points into Qdrant.

Search mode (``--query``)
    Run an interactive hybrid / dense-only / sparse-only search against
    the collection and pretty-print results to the terminal.

Usage examples::

    # Full index (code + patterns), first time
    cerberus-index --recreate

    # Incremental re-index (skips unchanged files)
    cerberus-index

    # Skip pattern mining
    cerberus-index --no-patterns

    # Hybrid search (default — dense + sparse → RRF fusion)
    cerberus-index --query "IPC dispatch loop pattern cerberus"

    # Dense-only search
    cerberus-index --query "how does the kernel handle page faults" --dense-only

    # Sparse-only search (exact symbols / keywords)
    cerberus-index --query "FixedFdTable register CapabilityId" --sparse-only

    # Search with filters
    cerberus-index --query "capability table" --type code_chunk --file "kernel/forge" --limit 15
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from cerberus_indexer.config import (
    COLLECTION_NAME,
    DENSE_MODEL,
    DENSE_VECTOR_NAME,
    EMBED_BATCH_SIZE,
    EMBEDDING_BACKEND,
    HYBRID_DEFAULT_LIMIT,
    NOTES_COLLECTION_NAME,
    QDRANT_API_KEY,
    QDRANT_URL,
    SPARSE_MODEL,
    UPSERT_WORKERS,
)
from cerberus_indexer.embeddings import EmbeddingManager
from cerberus_indexer.search import (
    dense_search,
    format_results,
    hybrid_search,
    sparse_search,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cerberus-index",
        description=(
            "Cerberus Qdrant indexer with hybrid sparse+dense search.\n\n"
            "Indexes the repository with both dense (MiniLM) and sparse (BM25)\n"
            "vectors, and provides hybrid search via Reciprocal Rank Fusion."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  # Full index (code + patterns)
  cerberus-index

  # Recreate collection from scratch
  cerberus-index --recreate

  # Index only, skip patterns
  cerberus-index --no-patterns

  # Hybrid search query
  cerberus-index --query "IPC dispatch loop pattern cerberus"

  # Hybrid search with type filter
  cerberus-index --query "capability ID allocation" --type code_chunk

  # Hybrid search with file filter
  cerberus-index --query "BTreeMap determinism" --file "fs-cbl"

  # Dense-only search (semantic)
  cerberus-index --query "how does IPC dispatch work" --dense-only

  # Sparse-only search (BM25 keyword)
  cerberus-index --query "FixedFdTable register" --sparse-only
""",
    )

    # -- Index mode flags ----------------------------------------------------
    idx_group = parser.add_argument_group("indexing options")
    idx_group.add_argument(
        "--recreate",
        action="store_true",
        help=(
            "Delete and recreate the code Qdrant collection before indexing.  "
            "Never touches the notes collection."
        ),
    )
    idx_group.add_argument(
        "--clear-notes",
        action="store_true",
        dest="clear_notes",
        help=(
            "Delete and recreate the notes collection, permanently erasing all "
            "agent memory/insights.  This is the only way to clear agent memory "
            "and is intentionally not available as an MCP tool."
        ),
    )
    idx_group.add_argument(
        "--no-code",
        action="store_true",
        help="Skip code-chunk indexing (patterns only).",
    )
    idx_group.add_argument(
        "--no-patterns",
        action="store_true",
        help="Skip pattern mining (code only).",
    )
    idx_group.add_argument(
        "--state-path",
        default=STATE_PATH_DEFAULT,
        help=f"Path to incremental state file (default: {STATE_PATH_DEFAULT}).",
    )
    idx_group.add_argument(
        "--repo-root",
        default=".",
        help="Path to the Cerberus repository root (default: current directory).",
    )
    idx_group.add_argument(
        "--collection",
        default=COLLECTION_NAME,
        dest="collection_name",
        help=f"Qdrant collection name (default: {COLLECTION_NAME}).",
    )

    # -- Model / backend flags -----------------------------------------------
    model_group = parser.add_argument_group("model / backend selection")
    model_group.add_argument(
        "--backend",
        type=str,
        default=EMBEDDING_BACKEND,
        choices=["fastembed", "sentence-transformers"],
        dest="backend",
        help=(
            f"Dense embedding backend: 'fastembed' (ONNX) or "
            f"'sentence-transformers' (PyTorch).  sentence-transformers "
            f"is required for models without ONNX weights in fastembed's "
            f"curated list (e.g. IBM Granite) (default: {EMBEDDING_BACKEND})."
        ),
    )
    model_group.add_argument(
        "--model",
        type=str,
        default=DENSE_MODEL,
        dest="dense_model",
        help=(f"HuggingFace model identifier for the dense encoder (default: {DENSE_MODEL})."),
    )

    # -- Pipeline tuning flags -----------------------------------------------
    perf_group = parser.add_argument_group("pipeline / performance tuning")
    perf_group.add_argument(
        "--embed-batch-size",
        type=int,
        default=EMBED_BATCH_SIZE,
        dest="embed_batch_size",
        help=(
            f"Number of text chunks to accumulate across files before "
            f"sending a single batch to the embedding model.  Larger "
            f"values improve GPU and ONNX throughput (default: {EMBED_BATCH_SIZE})."
        ),
    )
    perf_group.add_argument(
        "--upsert-workers",
        type=int,
        default=UPSERT_WORKERS,
        dest="upsert_workers",
        help=(
            f"Number of threads dedicated to Qdrant upsert I/O.  One "
            f"is usually enough for a local server; increase for remote "
            f"or high-latency Qdrant instances (default: {UPSERT_WORKERS})."
        ),
    )

    # -- Search mode flags ---------------------------------------------------
    search_group = parser.add_argument_group("search options")
    search_group.add_argument(
        "--query",
        type=str,
        default=None,
        help="Run a search query instead of indexing.",
    )
    search_group.add_argument(
        "--type",
        type=str,
        default=None,
        choices=["code_chunk", "pattern", "mcp_stored"],
        help="Filter search results by point type.",
    )
    search_group.add_argument(
        "--file",
        type=str,
        default=None,
        help="Filter search results by file path substring.",
    )
    search_group.add_argument(
        "--limit",
        type=int,
        default=HYBRID_DEFAULT_LIMIT,
        help=f"Number of search results to return (default: {HYBRID_DEFAULT_LIMIT}).",
    )
    search_group.add_argument(
        "--dense-only",
        action="store_true",
        help="Search using only dense vectors (no hybrid fusion).",
    )
    search_group.add_argument(
        "--sparse-only",
        action="store_true",
        help="Search using only sparse/BM25 vectors (no hybrid fusion).",
    )

    # -- Misc ----------------------------------------------------------------
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )

    return parser


# ---------------------------------------------------------------------------
# Search sub-command
# ---------------------------------------------------------------------------


def _run_search(args: argparse.Namespace) -> None:
    """Execute a search query and print results."""
    from qdrant_client import QdrantClient

    collection = args.collection_name
    query_text = args.query

    backend = getattr(args, "backend", EMBEDDING_BACKEND)
    dense_model = getattr(args, "dense_model", DENSE_MODEL)

    print(f"Qdrant URL       : {QDRANT_URL}")
    print(f"Collection       : {collection}")
    print(f"Backend          : {backend}")
    print(f"Dense model      : {dense_model}")
    print(f"Sparse model     : {SPARSE_MODEL}")
    print(f"Dense vector     : {DENSE_VECTOR_NAME}")
    print(f"Sparse vector    : {SPARSE_VECTOR_NAME}")

    client = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY)

    # Verify collection exists before spending time loading models.
    if not client.collection_exists(collection):
        print(
            f"\n❌ Collection '{collection}' does not exist. "
            "Run indexing first:\n\n"
            f"  cerberus-index --recreate --collection {collection}\n"
        )
        sys.exit(1)

    print("\n[model] Loading embedding models…")
    emb = EmbeddingManager(
        dense_model_name=dense_model,
        backend=backend,
    )

    print(f'\n🔍 Search: "{query_text}"')

    if args.dense_only and args.sparse_only:
        print("❌ Cannot use --dense-only and --sparse-only at the same time.")
        sys.exit(1)

    if args.dense_only:
        print("   Mode: dense-only (semantic)")
        results = dense_search(
            client=client,
            embeddings=emb,
            query_text=query_text,
            collection_name=collection,
            limit=args.limit,
            type_filter=args.type,
            file_filter=args.file,
        )
        mode_label = "dense-only"

    elif args.sparse_only:
        print("   Mode: sparse-only (BM25 keyword)")
        results = sparse_search(
            client=client,
            embeddings=emb,
            query_text=query_text,
            collection_name=collection,
            limit=args.limit,
            type_filter=args.type,
            file_filter=args.file,
        )
        mode_label = "sparse-only"

    else:
        print("   Mode: hybrid (dense + sparse → RRF fusion)")
        results = hybrid_search(
            client=client,
            embeddings=emb,
            query_text=query_text,
            collection_name=collection,
            limit=args.limit,
            type_filter=args.type,
            file_filter=args.file,
        )
        mode_label = "hybrid RRF"

    print(f"\n📋 Results ({len(results)} hits, {mode_label}):\n")
    print(format_results(results))
    print()


# ---------------------------------------------------------------------------
# Index sub-command
# ---------------------------------------------------------------------------


def _run_index(args: argparse.Namespace) -> None:
    """Execute the indexing pipeline."""
    # Import here so model loading only happens when actually indexing.
    from qdrant_client import QdrantClient

    from cerberus_indexer.indexer import run_index

    repo_root = Path(args.repo_root).resolve()

    backend = args.backend
    dense_model = args.dense_model

    print(f"Qdrant URL       : {QDRANT_URL}")
    print(f"Collection       : {args.collection_name}")
    print(f"Notes collection : {NOTES_COLLECTION_NAME}")
    print(f"Backend          : {backend}")
    print(f"Dense model      : {dense_model}")
    print(f"Sparse model     : {SPARSE_MODEL}")
    print(f"Dense vector     : {DENSE_VECTOR_NAME}")
    print(f"Sparse vector    : {SPARSE_VECTOR_NAME}")
    print(f"Repo root        : {repo_root}")

    # --clear-notes: delete the notes collection before indexing.
    if getattr(args, "clear_notes", False):
        client = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY)
        if client.collection_exists(NOTES_COLLECTION_NAME):
            client.delete_collection(NOTES_COLLECTION_NAME)
            print(
                f"⚠️  Notes collection '{NOTES_COLLECTION_NAME}' deleted "
                "(all agent memory erased)."
            )
        else:
            print(
                f"Notes collection '{NOTES_COLLECTION_NAME}' does not exist — "
                "nothing to clear."
            )

    run_index(
        repo_root=repo_root,
        recreate=args.recreate,
        skip_code=args.no_code,
        skip_patterns=args.no_patterns,
        state_path=args.state_path,
        collection_name=args.collection_name,
        embed_batch_size=args.embed_batch_size,
        upsert_workers=args.upsert_workers,
        backend=backend,
        dense_model=dense_model,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """
    Main entry point for the ``cerberus-index`` command.

    Dispatches to either search mode (``--query``) or index mode (default)
    based on the provided arguments.
    """
    parser = _build_parser()
    args = parser.parse_args()

    # -- Logging setup -------------------------------------------------------
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    # -- Dispatch ------------------------------------------------------------
    if args.query is not None:
        _run_search(args)
    else:
        _run_index(args)


if __name__ == "__main__":
    main()
