"""
Unified configuration for the Cerberus repository indexer and hybrid MCP server.

All tunables live here so that both the CLI indexer and the MCP server
share a single source of truth.  Environment variables override defaults.
"""

import logging
import os
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Qdrant connection
# ---------------------------------------------------------------------------

QDRANT_URL: str = os.getenv("QDRANT_URL", "http://qdrant.orbit.lfam.us:6333")
QDRANT_API_KEY: str | None = os.getenv("QDRANT_API_KEY")

# Default collection — may be overridden per-tool-call in the MCP server.
COLLECTION_NAME: str = os.getenv("COLLECTION_NAME", "cerberus-dev")

# Notes collection — holds agent memory/insights only.  Safe from --recreate.
# Defaults to "{COLLECTION_NAME}-notes" but can be overridden via env var.
NOTES_COLLECTION_NAME: str = os.getenv("NOTES_COLLECTION_NAME", f"{COLLECTION_NAME}-notes")

# ---------------------------------------------------------------------------
# Embedding models
# ---------------------------------------------------------------------------
#
# Backend selection — controls which library drives dense embedding:
#
#   EMBEDDING_BACKEND="fastembed"             (default) ONNX via fastembed
#   EMBEDDING_BACKEND="sentence-transformers" PyTorch via sentence-transformers
#
# sentence-transformers is required for models that don't ship ONNX
# weights in fastembed's curated list (e.g. ModernBERT-based models
# like IBM Granite).
#
# Install the optional extra:
#   pip install -e ".[st]"
# ---------------------------------------------------------------------------

EMBEDDING_BACKEND: str = os.getenv("EMBEDDING_BACKEND", "fastembed").strip().lower()

_VALID_BACKENDS = {"fastembed", "sentence-transformers"}
if EMBEDDING_BACKEND not in _VALID_BACKENDS:
    logger.warning(
        "Unknown EMBEDDING_BACKEND '%s' — falling back to 'fastembed'. Valid values: %s",
        EMBEDDING_BACKEND,
        _VALID_BACKENDS,
    )
    EMBEDDING_BACKEND = "fastembed"

DENSE_MODEL: str = os.getenv("EMBEDDING_MODEL", "nomic-ai/nomic-embed-text-v1.5")
SPARSE_MODEL: str = os.getenv("SPARSE_MODEL", "Qdrant/bm25")

# Named vector keys — must match between indexer and server.
# The dense name follows the fastembed convention used by the upstream
# mcp-server-qdrant so that collections created by *either* tool are
# queryable by the other.  When using sentence-transformers we prefix
# with "st-" instead of "fast-" so the two backends produce distinct
# collection layouts (avoids dimension mismatches on upgrade).
_model_slug = DENSE_MODEL.split("/")[-1].lower()
_vector_prefix = "st" if EMBEDDING_BACKEND == "sentence-transformers" else "fast"
DENSE_VECTOR_NAME: str = f"{_vector_prefix}-{_model_slug}"
SPARSE_VECTOR_NAME: str = "bm25"

logger.info(
    "Embedding backend: %s | model: %s | dense vector name: %s",
    EMBEDDING_BACKEND,
    DENSE_MODEL,
    DENSE_VECTOR_NAME,
)

# ---------------------------------------------------------------------------
# ONNX Runtime execution providers (GPU acceleration)
# ---------------------------------------------------------------------------
#
# The indexer attempts GPU inference by default and falls back to CPU
# automatically.  Set ``ONNX_PROVIDERS`` to override detection, e.g.:
#
#   ONNX_PROVIDERS="CUDAExecutionProvider,CPUExecutionProvider"
#
# To force CPU-only (useful for CI or headless machines):
#
#   ONNX_PROVIDERS="CPUExecutionProvider"
#
# GPU requires ``onnxruntime-gpu`` (CUDA) or ``onnxruntime-directml``
# (Windows/DirectX) installed *instead of* the plain ``onnxruntime``
# package.  When neither is present the auto-detection gracefully
# falls back to CPU.
# ---------------------------------------------------------------------------

# Provider priority — highest-throughput first, CPU always last.
_GPU_PROVIDER_PRIORITY: List[str] = [
    "TensorrtExecutionProvider",
    "CUDAExecutionProvider",
    "DmlExecutionProvider",
    "ROCMExecutionProvider",
]


def _detect_onnx_providers() -> List[str]:
    """
    Auto-detect available ONNX Runtime execution providers.

    Tries GPU providers in priority order (TensorRT > CUDA > DirectML >
    ROCm) and always appends ``CPUExecutionProvider`` as a fallback.

    Returns
    -------
    List[str]
        Ordered list of provider names suitable for passing to
        ``onnxruntime.InferenceSession`` (via fastembed's ``providers``
        kwarg).
    """
    try:
        import onnxruntime as ort

        available = set(ort.get_available_providers())
    except ImportError:
        logger.debug("onnxruntime not importable — defaulting to CPU provider list.")
        return ["CPUExecutionProvider"]

    providers: List[str] = []
    for p in _GPU_PROVIDER_PRIORITY:
        if p in available:
            providers.append(p)

    # CPU is always the final fallback.
    if "CPUExecutionProvider" not in providers:
        providers.append("CPUExecutionProvider")

    return providers


def _parse_onnx_providers_env(raw: str) -> List[str]:
    """Parse a comma-separated ``ONNX_PROVIDERS`` env var into a list."""
    return [p.strip() for p in raw.split(",") if p.strip()]


_onnx_env: Optional[str] = os.getenv("ONNX_PROVIDERS")

if _onnx_env:
    ONNX_PROVIDERS: List[str] = _parse_onnx_providers_env(_onnx_env)
    logger.info("ONNX providers (from env): %s", ONNX_PROVIDERS)
else:
    ONNX_PROVIDERS: List[str] = _detect_onnx_providers()
    # Log once at import time so the user knows what was selected.
    _gpu_selected = [p for p in ONNX_PROVIDERS if p != "CPUExecutionProvider"]
    if _gpu_selected:
        logger.info(
            "ONNX GPU provider auto-detected: %s (CPU fallback enabled)",
            _gpu_selected,
        )
    else:
        logger.info(
            "No GPU provider found — using CPUExecutionProvider. "
            "Install onnxruntime-gpu for CUDA acceleration."
        )

# Intra-op thread count for ONNX Runtime.  ``None`` lets ONNX Runtime
# pick a default (usually = physical core count).  Override with e.g.
# ``ONNX_THREADS=4`` to cap CPU usage during indexing.
_onnx_threads_env: Optional[str] = os.getenv("ONNX_THREADS")
ONNX_THREADS: Optional[int] = int(_onnx_threads_env) if _onnx_threads_env else None

# ---------------------------------------------------------------------------
# Code-chunk indexing scope
# ---------------------------------------------------------------------------

INCLUDE_EXTENSIONS: set[str] = {
    ".rs",
    ".toml",
    ".md",
    ".sh",
    ".txt",
    ".json",
    ".yml",
    ".yaml",
}

INCLUDE_FILENAMES: set[str] = {
    "ledgerfs-spec",
    "ledgerfs-spec-v7.md",
    ".cerberus-config",
    "mcp-qdrant-cerberus",
}

EXCLUDE_DIRS: set[str] = {
    "target",
    ".git",
    "qdrant_storage",
    ".cargo",
    ".venv",
    "__pycache__",
}

# Path-prefix exclusions — checked with ``str(path).startswith(…)``.
# Unlike ``EXCLUDE_DIRS`` (which matches individual directory components),
# these match against the full repo-relative path so you can target a
# specific subtree without accidentally excluding unrelated dirs that
# happen to share a component name.
EXCLUDE_PATHS: set[str] = {
    "tools/indexer",  # Don't index the indexer itself
}

INCLUDE_PATHS: set[str] = {
    "cerberus/kernel/forge",
    "cerberus/kernel/forge-boot",
    "cerberus/kernel/forge-builder",
    "cerberus/kernel/forge-drivers",
    "cerberus/kernel/forge-init",
    "cerberus/kernel/forge-rc",
    "cerberus/kernel/ledgerfs",
    "cerberus/crucibles",
    "cerberus/crypto",
    "cerberus/runtime",
    "cerberus/misc",
    "library/std/src/sys/pal/cerberus",
    "library/std/src/sys/alloc",
    "tools",
    "tests",
    "docs",
    "profiles",
    "targets",
}

# ---------------------------------------------------------------------------
# Pattern mining scope
# ---------------------------------------------------------------------------

PATTERN_CODE_SCOPES: set[str] = {
    "cerberus/crucibles",
    "cerberus/kernel/forge",
    "cerberus/kernel/ledgerfs",
    "cerberus/runtime/temper",
}

PATTERN_DOC_SCOPES: set[str] = {
    "docs",
    ".github",
    "cerberus/crucibles",
    "cerberus/runtime",
    "cerberus/kernel",
}

# Vendored / third-party trees that should never be pattern-mined.
PATTERN_EXCLUDE_DIRS: set[str] = {
    "library",
    "cerberus/crypto/crypto-curve25519-dalek",
    "cerberus/crypto/crypto-p256",
    "cerberus/crypto/crypto-p384",
}

# ---------------------------------------------------------------------------
# Chunking parameters
#
# Most embedding models support ≥512 tokens.  Code averages ~2.5
# subword tokens per whitespace word, so 512 words ≈ 1280 tokens —
# well within model windows (nomic: 8192, granite-small-r2: 8192,
# bge-base: 512).
#
# If your model is memory-heavy (e.g. nomic on CPU), lower this:
#   CHUNK_WORDS=256 CHUNK_OVERLAP=32 cerberus-index --recreate
# ---------------------------------------------------------------------------

CHUNK_WORDS: int = int(os.getenv("CHUNK_WORDS", "512"))
CHUNK_OVERLAP: int = int(os.getenv("CHUNK_OVERLAP", "64"))

# ---------------------------------------------------------------------------
# Upsert batching
# ---------------------------------------------------------------------------

BATCH_SIZE: int = 64

# ---------------------------------------------------------------------------
# Pipeline parameters (embedding + upsert)
# ---------------------------------------------------------------------------

# Number of text chunks to accumulate across files before sending a
# single batch to the embedding model.  Larger batches improve GPU and
# ONNX Runtime throughput (better memory locality, amortised overhead).
# Set via ``EMBED_BATCH_SIZE`` env var.  Default of 256 is a good
# balance between memory usage and throughput.
EMBED_BATCH_SIZE: int = int(os.getenv("EMBED_BATCH_SIZE", "256"))

# Maximum number of batches that can sit in inter-stage queues before
# the producing side blocks.  Keeps memory bounded.
PIPELINE_QUEUE_DEPTH: int = int(os.getenv("PIPELINE_QUEUE_DEPTH", "2"))

# Number of dedicated threads for Qdrant upsert I/O in the pipeline.
# One is typically sufficient for a local Qdrant instance; increase for
# remote / high-latency servers.
UPSERT_WORKERS: int = int(os.getenv("UPSERT_WORKERS", "1"))

# ---------------------------------------------------------------------------
# Incremental state file
# ---------------------------------------------------------------------------

STATE_PATH_DEFAULT: str = ".qdrant-index-state.json"

# ---------------------------------------------------------------------------
# Repo root (used by the MCP server for incremental re-indexing)
# ---------------------------------------------------------------------------
#
# The launcher script ``mcp-server-cerberus`` exports ``CERBERUS_REPO_ROOT``
# before exec-ing this module.  If the variable is not set (e.g. during
# testing or direct invocation) we fall back to the current working directory.
# ---------------------------------------------------------------------------

CERBERUS_REPO_ROOT: Path = Path(os.getenv("CERBERUS_REPO_ROOT", str(Path.cwd())))

# ---------------------------------------------------------------------------
# Hybrid search defaults
# ---------------------------------------------------------------------------

# Number of candidate results fetched per search leg (dense / sparse)
# before Reciprocal Rank Fusion merges them.
HYBRID_PREFETCH_LIMIT: int = 40

# Final result count returned to the caller.
HYBRID_DEFAULT_LIMIT: int = 10

# ---------------------------------------------------------------------------
# Response budget
# ---------------------------------------------------------------------------

# Absolute ceiling on response size in characters.  The intelligent budget
# system (budget.py) uses this as the hard cap across all presets.
# Override with the ``MAX_RESPONSE_CHARS`` environment variable.
DEFAULT_MAX_RESPONSE_CHARS: int = int(os.getenv("MAX_RESPONSE_CHARS", "12000"))

# ---------------------------------------------------------------------------
# MCP tool descriptions (shown to the LLM by the MCP host)
# ---------------------------------------------------------------------------

TOOL_MEMORY_DESCRIPTION: str = os.getenv(
    "TOOL_MEMORY_DESCRIPTION",
    (
        "Agent memory — persist insights, architecture decisions, "
        "cross-cutting observations, and session notes into a dedicated "
        "notes collection so they are discoverable by future searches.  "
        "NOT for indexing source files (use qdrant-reindex for that).  "
        "Use 'information' for a natural-language description of the "
        "insight and 'metadata' for structured context (related files, "
        "symbols, decision rationale, etc.).  Stored notes appear in "
        "cerberus-search results alongside code chunks."
    ),
)

TOOL_REINDEX_DESCRIPTION: str = os.getenv(
    "TOOL_REINDEX_DESCRIPTION",
    (
        "Incrementally re-index the Cerberus repository into Qdrant.  "
        "Detects files that changed since the last index run (via "
        "BLAKE2s content hashing) and only re-embeds/upserts those — "
        "unchanged files are skipped.  Call this after making code "
        "changes to keep cerberus-search results up to date.  Returns "
        "a summary of files updated, deleted, and skipped.  Set "
        "reindex_patterns=true to also re-mine architecture patterns "
        "(slower, usually not needed for small edits)."
    ),
)

TOOL_SEARCH_DESCRIPTION: str = os.getenv(
    "TOOL_SEARCH_DESCRIPTION",
    (
        "Primary search tool for Cerberus code.  Supports filtering by "
        "subsystem, crate, or structural kind.  Filter parameters:\n"
        "  subsystem: 'kernel' | 'runtime' | 'crucibles' | 'crypto' | 'tools' | "
        "'tests' | 'docs' | 'library'\n"
        "  crate: e.g. 'forge-boot' | 'forge-rc' | 'ledgerfs' | 'forge-init'\n"
        "  kind: 'function' | 'struct' | 'impl' | 'enum' | 'trait' | 'module' | "
        "'const' | 'test' | 'mixed'\n"
        "  symbols: comma-separated symbol names to match (e.g. 'entry_point,init')\n"
        "  file_path: substring of the file path\n"
        "  exclude_tests: true to exclude chunks with ``metadata.is_test == True``.\n"
        "  limit: max results (default 15)\n"
        "  max_response_chars: cap response size (default auto-detected based on query)\n"
        "Results include file path, line range, crate, subsystem, and defined symbols."
    ),
)

TOOL_TRACE_DESCRIPTION: str = os.getenv(
    "TOOL_TRACE_DESCRIPTION",
    (
        "Trace call chains in Cerberus code.  Given a symbol name, "
        "finds where it is defined and who calls it (or what it calls), "
        "up to a configurable depth.  Parameters:\n"
        "  symbol: the function/struct/type name to trace\n"
        "  direction: 'callers' | 'callees' | 'both' (default 'both')\n"
        "  depth: recursion depth (default 2, max 4)\n"
        "  subsystem: optional subsystem filter\n"
        "  max_response_chars: cap response size (default 16000)\n"
        "Use this to understand control flow, identify entry points, and "
        "map how components are connected."
    ),
)

# Metadata payload key — matches upstream mcp-server-qdrant convention
# so points created by either tool look the same.
METADATA_PATH: str = "metadata"
