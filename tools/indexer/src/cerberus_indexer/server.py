"""
CerberusOS Hybrid MCP Server — drop-in replacement for mcp-server-qdrant.

This server exposes the ``cerberus-search`` (legacy: ``crucible-search``), ``trace``, ``memory``, and
``qdrant-reindex`` MCP tools with a critical upgrade over vanilla
mcp-server-qdrant: **all searches use hybrid dense + sparse (BM25) retrieval
fused with Reciprocal Rank Fusion (RRF)** instead of dense-only cosine search.

The ``memory`` tool writes agent notes to a dedicated notes collection
(``NOTES_COLLECTION_NAME``) that is never touched by ``--recreate``, so
accumulated insights survive full re-indexes.  ``cerberus-search`` (legacy: ``crucible-search``) queries
both the code collection and the notes collection, merging results with RRF.

Architecture
~~~~~~~~~~~~
- Built on the ``mcp`` Python SDK (FastMCP flavour).
- Lazily initialises both fastembed models (dense MiniLM + sparse BM25)
  on first tool call.
- Embedding happens in a thread executor so the asyncio event loop is
  never blocked.
- Qdrant queries use the synchronous ``QdrantClient`` dispatched to a
  thread executor (the async client has edge-case issues with some
  transports; this is the same approach upstream uses).

Transport
~~~~~~~~~
Designed for ``--transport stdio`` when launched by Zed / Claude Desktop /
Cursor, but also supports ``sse`` and ``streamable-http`` via the FastMCP
CLI flags.

Environment Variables
~~~~~~~~~~~~~~~~~~~~~
All configuration comes from :mod:`cerberus_indexer.config`, which reads
from environment variables with sensible defaults.  The launcher script
``mcp-server-cerberus`` sets these before ``exec``-ing this module.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
import re
import sys
import uuid
from typing import Any, List, Optional

from mcp.server.fastmcp import FastMCP
from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from cerberus_indexer.config import (
    CERBERUS_REPO_ROOT,
    COLLECTION_NAME,
    DEFAULT_MAX_RESPONSE_CHARS,
    DENSE_VECTOR_NAME,
    HYBRID_PREFETCH_LIMIT,
    METADATA_PATH,
    NOTES_COLLECTION_NAME,
    QDRANT_API_KEY,
    QDRANT_URL,
    SPARSE_VECTOR_NAME,
    TOOL_TRACE_DESCRIPTION,
)
from cerberus_indexer.embeddings import EmbeddingManager

logger = logging.getLogger(__name__)

# Regex to extract a Rust function signature from chunk text.
_SIG_RE = re.compile(
    r"(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+\w+[^{;]*",
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# FastMCP application
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "cerberus-qdrant",
    dependencies=["fastembed", "qdrant-client"],
)
# Note: historically this service identified as "crucible-qdrant".
# We keep the MCP tool names compatible (cerberus-search / legacy: crucible-search)
# so older clients can continue to interact. The instance now advertises
# itself as "cerberus-qdrant".

# ---------------------------------------------------------------------------
# Lazy singletons
#
# These are initialised on first use rather than at import time so that
# (a) model download only happens when a tool is actually called, and
# (b) import is fast for the MCP handshake.
# ---------------------------------------------------------------------------

_qdrant_client: Optional[QdrantClient] = None
_embedding_mgr: Optional[EmbeddingManager] = None


def _get_client() -> QdrantClient:
    """Return the shared Qdrant client, creating it on first call."""
    global _qdrant_client
    if _qdrant_client is None:
        logger.info("Connecting to Qdrant at %s", QDRANT_URL)
        _qdrant_client = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY)
    return _qdrant_client


def _get_embeddings() -> EmbeddingManager:
    """Return the shared embedding manager, loading models on first call."""
    global _embedding_mgr
    if _embedding_mgr is None:
        logger.info("Loading dense + sparse embedding models…")
        _embedding_mgr = EmbeddingManager()
        # Force model load now so the first real query is fast.
        _ = _embedding_mgr.dense_dim
        logger.info("Models loaded. Dense dim = %d", _embedding_mgr.dense_dim)
    return _embedding_mgr


# ---------------------------------------------------------------------------
# Collection auto-creation
# ---------------------------------------------------------------------------


async def _ensure_collection(client: QdrantClient, collection_name: str) -> None:
    """
    Ensure *collection_name* exists with hybrid vector config.

    If the collection doesn't exist it is created.  If it exists but
    lacks the sparse vector configuration it is migrated automatically.
    This mirrors :func:`cerberus_indexer.qdrant_ops.ensure_collection`
    but runs inside the async server context.
    """
    loop = asyncio.get_event_loop()

    def _sync_ensure() -> None:
        emb = _get_embeddings()
        if not client.collection_exists(collection_name):
            client.create_collection(
                collection_name=collection_name,
                vectors_config={
                    DENSE_VECTOR_NAME: qmodels.VectorParams(
                        size=emb.dense_dim,
                        distance=qmodels.Distance.COSINE,
                    ),
                },
                sparse_vectors_config={
                    SPARSE_VECTOR_NAME: qmodels.SparseVectorParams(
                        index=qmodels.SparseIndexParams(on_disk=False),
                    ),
                },
            )
            logger.info("Created collection '%s' with hybrid vectors.", collection_name)
        else:
            info = client.get_collection(collection_name)
            existing_sparse: set[str] = set()
            if info.config.params.sparse_vectors:
                existing_sparse = set(info.config.params.sparse_vectors.keys())
            if SPARSE_VECTOR_NAME not in existing_sparse:
                client.update_collection(
                    collection_name=collection_name,
                    sparse_vectors_config={
                        SPARSE_VECTOR_NAME: qmodels.SparseVectorParams(
                            index=qmodels.SparseIndexParams(on_disk=False),
                        ),
                    },
                )
                logger.info(
                    "Added sparse vector '%s' to collection '%s'.",
                    SPARSE_VECTOR_NAME,
                    collection_name,
                )

    await loop.run_in_executor(None, _sync_ensure)


# ---------------------------------------------------------------------------
# Helper: resolve collection name
# ---------------------------------------------------------------------------


def _resolve_collection(collection_name: Optional[str]) -> str:
    """Return *collection_name* if given, else the default from config."""
    return collection_name or COLLECTION_NAME


# ---------------------------------------------------------------------------
# Tool: cerberus-search  (domain-aware hybrid search with filters)
# ---------------------------------------------------------------------------


@mcp.tool(name="cerberus-search", description=TOOL_SEARCH_DESCRIPTION)
async def cerberus_search(
    query: str,
    subsystem: Optional[str] = None,
    crate: Optional[str] = None,
    kind: Optional[str] = None,
    symbols: Optional[str] = None,
    file_path: Optional[str] = None,
    exclude_tests: bool = False,
    limit: int = 15,
    collection_name: Optional[str] = None,
    max_response_chars: Optional[int] = None,
) -> str:
    """
    Domain-aware hybrid search for Cerberus code.

    Parameters
    ----------
    query:
        Natural-language search query.
    subsystem:
        Optional subsystem filter: ``"kernel"``, ``"runtime"``,
        ``"crucibles"``, ``"crypto"``, ``"tools"``, ``"tests"``,
        ``"docs"``, ``"library"``.
    crate:
        Optional crate name filter (e.g. ``"forge-boot"``).
    kind:
        Optional structural kind: ``"function"``, ``"struct"``,
        ``"impl"``, ``"enum"``, ``"trait"``, ``"module"``, ``"const"``,
        ``"test"``, ``"mixed"``.
    symbols:
        Comma-separated symbol names to match against ``metadata.symbols``.
    file_path:
        Substring filter on the file path.
    exclude_tests:
        If ``True``, exclude chunks with ``metadata.is_test == True``.
    limit:
        Maximum number of results to return.
    collection_name:
        Qdrant collection to search (defaults to the configured
        ``COLLECTION_NAME``).
    max_response_chars:
        Hard cap on response size in characters.  Overrides the preset
        budget derived from query intent.  Defaults to auto-detection.
    """
    from cerberus_indexer.budget import (
        BUDGET_PRESETS,
        TieredBudget,
        detect_score_cliff,
        estimate_query_intent,
    )

    coll = _resolve_collection(collection_name)
    client = _get_client()
    emb_mgr = _get_embeddings()

    loop = asyncio.get_event_loop()

    # Embed the query.
    emb = await emb_mgr.aembed_query(query)

    # Build filters.
    from cerberus_indexer.search import _build_filter

    sym_list: Optional[List[str]] = (
        [s.strip() for s in symbols.split(",") if s.strip()] if symbols else None
    )
    search_filter = _build_filter(
        file_filter=file_path,
        subsystem=subsystem,
        crate=crate,
        kind=kind,
        symbols=sym_list,
        exclude_tests=exclude_tests,
    )

    prefetches = [
        qmodels.Prefetch(
            query=emb.dense.values,
            using=DENSE_VECTOR_NAME,
            limit=HYBRID_PREFETCH_LIMIT,
            filter=search_filter,
        ),
        qmodels.Prefetch(
            query=emb.sparse.to_qdrant(),
            using=SPARSE_VECTOR_NAME,
            limit=HYBRID_PREFETCH_LIMIT,
            filter=search_filter,
        ),
    ]

    def _query() -> list[qmodels.ScoredPoint]:
        if not client.collection_exists(coll):
            return []
        code_results = client.query_points(
            collection_name=coll,
            prefetch=prefetches,
            query=qmodels.FusionQuery(fusion=qmodels.Fusion.RRF),
            limit=limit,
            with_payload=True,
        ).points

        # Also search the notes collection and merge results.
        notes_results: list[qmodels.ScoredPoint] = []
        if client.collection_exists(NOTES_COLLECTION_NAME):
            try:
                notes_results = client.query_points(
                    collection_name=NOTES_COLLECTION_NAME,
                    prefetch=prefetches,
                    query=qmodels.FusionQuery(fusion=qmodels.Fusion.RRF),
                    limit=limit,
                    with_payload=True,
                ).points
            except Exception:
                logger.warning(
                    "Notes collection '%s' search failed; skipping.",
                    NOTES_COLLECTION_NAME,
                    exc_info=True,
                )

        if not notes_results:
            return code_results

        from cerberus_indexer.search import _rrf_merge

        return _rrf_merge([code_results, notes_results], limit=limit)

    points = await loop.run_in_executor(None, _query)

    if not points:
        return f"No results found in collection '{coll}' for query: {query}"

    total_found = len(points)

    # ------------------------------------------------------------------
    # Layer 2 (P1): Score-cliff detection — drop results below the cliff.
    # ------------------------------------------------------------------
    scores = [pt.score for pt in points]
    cliff_idx = detect_score_cliff(scores)
    points = points[:cliff_idx]

    # ------------------------------------------------------------------
    # Layer 3 (P2): Intent classification + preset selection.
    # ------------------------------------------------------------------
    intent = estimate_query_intent(query, symbols, kind)
    preset = BUDGET_PRESETS[intent]

    # Honour limit_override from the preset.
    limit_override = preset.get("limit_override")
    if limit_override is not None and limit_override < len(points):
        points = points[:limit_override]

    # Determine effective budget: caller > env-var ceiling.
    preset_budget: int = preset["total_budget"]
    hard_cap: int = (
        max_response_chars if max_response_chars is not None else DEFAULT_MAX_RESPONSE_CHARS
    )
    effective_budget = min(preset_budget, hard_cap)

    # ------------------------------------------------------------------
    # Format each result (full content for all — tiering applied below).
    # ------------------------------------------------------------------
    formatted: list[str] = []
    meta_list: list[dict] = []

    for i, pt in enumerate(points, 1):
        payload = pt.payload or {}
        ptype = payload.get("type", "unknown")
        score = pt.score

        if ptype == "code_chunk":
            meta = payload.get(METADATA_PATH, {}) or {}
            file_p = meta.get("file", "?")
            chunk_idx = meta.get("chunk_index", "?")
            total = meta.get("total_chunks", "?")
            lang = meta.get("language", "?")
            sub = meta.get("subsystem", "")
            crate_m = meta.get("crate", "")
            syms = meta.get("symbols", [])
            line_s = meta.get("line_start", "?")
            line_e = meta.get("line_end", "?")
            content = payload.get("document", "")
            header_parts = [f"File: {file_p} | Chunk {chunk_idx}/{total} | {lang}"]
            if sub or crate_m:
                header_parts.append(f"Subsystem: {sub} | Crate: {crate_m}")
            if syms:
                header_parts.append(f"Symbols: {', '.join(syms)}")
            if line_s != "?" or line_e != "?":
                header_parts.append(f"Lines: {line_s}–{line_e}")
            formatted.append("\n".join(header_parts) + f"\nContent:\n{content}")
            meta_list.append(meta)
        elif ptype == "pattern":
            name = payload.get("pattern_name", "?")
            reason = payload.get("reason", "")
            tags = payload.get("tags", [])
            snippet = payload.get("snippet", "")
            evidence = payload.get("evidence", [])
            ev_text = ""
            for ev in evidence[:5]:
                ev_text += f"  - {ev.get('file_path', '?')}:{ev.get('line_start', '?')} {ev.get('code_snippet', '')}\n"
            formatted.append(
                f"Pattern: {name}\n"
                f"Reason: {reason}\n"
                f"Tags: {', '.join(tags)}\n"
                f"Snippet: {snippet}\n"
                f"Evidence ({len(evidence)} hits):\n{ev_text}"
            )
            meta_list.append({})
        elif ptype == "mcp_stored":
            content = payload.get("document", "")
            meta = payload.get(METADATA_PATH) or {}
            meta_str = json.dumps(meta, indent=2) if meta else "(none)"
            formatted.append(f"Stored Information:\n{content}\nMetadata:\n{meta_str}")
            meta_list.append(meta if isinstance(meta, dict) else {})
        else:
            formatted.append(
                f"Type: {ptype}\nPayload: {json.dumps(payload, indent=2, default=str)}"
            )
            meta_list.append({})

    # ------------------------------------------------------------------
    # Layer 2 (P1): Tiered budget allocation.
    # ------------------------------------------------------------------
    tiered_scores = [pt.score for pt in points]
    items = list(zip(tiered_scores, formatted, meta_list))

    tiered_budget = TieredBudget(
        total_budget=effective_budget,
        tier1_budget_pct=preset["tier1_budget_pct"],
        tier2_budget_pct=preset["tier2_budget_pct"],
        tier3_budget_pct=preset["tier3_budget_pct"],
    )
    allocations = tiered_budget.allocate(items)

    parts: list[str] = []
    for i, (pt, (tier_label, output_text)) in enumerate(zip(points, allocations), 1):
        score = pt.score
        parts.append(f"--- Result {i} (score {score:.4f}, {tier_label}) ---\n{output_text}")

    response = "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Layer 1 (P0): Hard cap — truncate at last complete ``--- Result``
    # boundary to avoid mid-chunk cuts.
    # ------------------------------------------------------------------
    if len(response) > hard_cap:
        boundary = "--- Result "
        cutoff = response.rfind(boundary, 0, hard_cap)
        if cutoff > 0:
            response = response[:cutoff].rstrip()
        else:
            response = response[:hard_cap]
        shown = response.count("--- Result ")
        response += (
            f"\n\n[Truncated: showing {shown} of {total_found} results. "
            "Use filters (crate=, kind=, subsystem=) or increase max_response_chars to narrow results.]"
        )

    return response


# ---------------------------------------------------------------------------
# Tool: trace  (call-chain traversal)
# ---------------------------------------------------------------------------


@mcp.tool(name="trace", description=TOOL_TRACE_DESCRIPTION)
async def trace(
    symbol: str,
    direction: str = "both",
    depth: int = 2,
    subsystem: Optional[str] = None,
    collection_name: Optional[str] = None,
    max_response_chars: Optional[int] = None,
) -> str:
    """
    Trace call chains for *symbol* in the CerberusOS codebase.

    Parameters
    ----------
    symbol:
        The function/struct/type name to trace.
    direction:
        ``"callers"`` — find chunks that call *symbol*;
        ``"callees"`` — find what *symbol* calls;
        ``"both"`` — both directions (default).
    depth:
        Recursion depth (default 2, capped at 4 to avoid runaway queries).
    subsystem:
        Optional subsystem filter applied to all lookups.
    collection_name:
        Qdrant collection to search.
    max_response_chars:
        Hard cap on response size in characters.  Defaults to the
        ``"trace"`` preset budget (16000) or ``DEFAULT_MAX_RESPONSE_CHARS``,
        whichever is smaller.
    """
    from cerberus_indexer.budget import BUDGET_PRESETS

    trace_preset_budget: int = BUDGET_PRESETS["trace"]["total_budget"]
    hard_cap: int = (
        max_response_chars
        if max_response_chars is not None
        else min(trace_preset_budget, DEFAULT_MAX_RESPONSE_CHARS)
    )

    coll = _resolve_collection(collection_name)
    client = _get_client()

    depth = min(max(depth, 1), 4)
    loop = asyncio.get_event_loop()

    def _scroll_filter(flt: qmodels.Filter) -> list:
        """Return all points matching *flt* (scroll, not vector search)."""
        if not client.collection_exists(coll):
            return []
        points: list = []
        offset = None
        while True:
            batch, next_offset = client.scroll(
                collection_name=coll,
                scroll_filter=flt,
                limit=100,
                offset=offset,
                with_payload=True,
            )
            points.extend(batch)
            if next_offset is None:
                break
            offset = next_offset
        return points

    def _definitions_of(sym: str) -> list:
        """Find all chunks that define *sym* in metadata.symbols (traceable only)."""
        conditions = [
            qmodels.FieldCondition(
                key=f"{METADATA_PATH}.symbols",
                match=qmodels.MatchValue(value=sym),
            )
        ]
        if subsystem:
            conditions.append(
                qmodels.FieldCondition(
                    key=f"{METADATA_PATH}.subsystem",
                    match=qmodels.MatchValue(value=subsystem),
                )
            )
        return _scroll_filter(qmodels.Filter(must=conditions))

    def _callers_of(sym: str) -> list:
        """Find all chunks whose metadata.calls contains *sym*."""
        conditions = [
            qmodels.FieldCondition(
                key=f"{METADATA_PATH}.calls",
                match=qmodels.MatchValue(value=sym),
            )
        ]
        if subsystem:
            conditions.append(
                qmodels.FieldCondition(
                    key=f"{METADATA_PATH}.subsystem",
                    match=qmodels.MatchValue(value=subsystem),
                )
            )
        return _scroll_filter(qmodels.Filter(must=conditions))

    def _extract_signature(document: str) -> str:
        """Extract the first Rust function signature from *document*."""
        m = _SIG_RE.search(document)
        return m.group(0).strip() if m else ""

    def _format_node(pt, idx: int) -> str:
        """Format a single trace node with file, lines, kind, and snippet."""
        payload = pt.payload or {}
        meta = payload.get(METADATA_PATH, {}) or {}
        file_p = meta.get("file", "?")
        syms = meta.get("symbols", [])
        line_s = meta.get("line_start", "?")
        line_e = meta.get("line_end", "?")
        kind = meta.get("kind", "?")
        document = payload.get("document", "")
        sig = _extract_signature(document)
        name = syms[0] if syms else "(unnamed)"
        node_lines = [
            f"  {idx}. {name}",
            f"     File: {file_p}:{line_s}-{line_e}",
            f"     Kind: {kind}",
        ]
        if sig:
            node_lines.append(f"     Signature: {sig}")
        elif document:
            first_line = document.split("\n")[0][:120]
            node_lines.append(f"     Snippet: {first_line}")
        return "\n".join(node_lines)

    def _trace_callees(
        sym: str,
        current_depth: int,
        visited: set,
        output: list,
        idx_counter: list,
    ) -> None:
        """Recursively collect callee nodes for *sym*."""
        if current_depth == 0:
            return
        defs = _definitions_of(sym)
        for pt in defs[:3]:
            pt_id = str(pt.id)
            if pt_id in visited:
                continue
            visited.add(pt_id)
            output.append(_format_node(pt, idx_counter[0]))
            idx_counter[0] += 1
            payload = pt.payload or {}
            meta = payload.get(METADATA_PATH, {}) or {}
            called = meta.get("calls", [])
            unique_called = list(dict.fromkeys(called))[:10]
            if unique_called and current_depth > 1:
                for callee in unique_called[:5]:
                    _trace_callees(callee, current_depth - 1, visited, output, idx_counter)

    def _trace_callers(
        sym: str,
        current_depth: int,
        visited: set,
        output: list,
        idx_counter: list,
    ) -> None:
        """Recursively collect caller nodes for *sym*."""
        if current_depth == 0:
            return
        callers = _callers_of(sym)
        for pt in callers[:5]:
            pt_id = str(pt.id)
            if pt_id in visited:
                continue
            visited.add(pt_id)
            output.append(_format_node(pt, idx_counter[0]))
            idx_counter[0] += 1
            payload = pt.payload or {}
            meta = payload.get(METADATA_PATH, {}) or {}
            caller_syms = meta.get("symbols", [])
            if current_depth > 1:
                for caller_sym in caller_syms[:3]:
                    _trace_callers(caller_sym, current_depth - 1, visited, output, idx_counter)

    def _run_trace() -> str:
        output_lines = [f"═══ TRACE: {symbol!r} (direction={direction}, depth={depth}) ═══"]

        # Show the definition of the target symbol.
        defs = _definitions_of(symbol)
        if defs:
            pt = defs[0]
            payload = pt.payload or {}
            meta = payload.get(METADATA_PATH, {}) or {}
            file_p = meta.get("file", "?")
            line_s = meta.get("line_start", "?")
            line_e = meta.get("line_end", "?")
            kind = meta.get("kind", "?")
            module = meta.get("module_path", "")
            document = payload.get("document", "")
            sig = _extract_signature(document)
            output_lines.append("\n── DEFINITION ──")
            output_lines.append(f"File: {file_p}")
            output_lines.append(f"Lines: {line_s}-{line_e}")
            output_lines.append(f"Kind: {kind}")
            if module:
                output_lines.append(f"Module: {module}")
            if sig:
                output_lines.append(f"Signature: {sig}")
        else:
            output_lines.append(f"\n[No definition found for {symbol!r}]")

        # Track visited chunks by point ID to avoid duplicates and infinite loops.
        visited: set[str] = set()

        if direction in ("callees", "both"):
            output_lines.append("\n── CALLEES (functions this calls) ──")
            callee_entries: list[str] = []
            _trace_callees(symbol, depth, visited, callee_entries, [1])
            if callee_entries:
                output_lines.extend(callee_entries)
            else:
                output_lines.append("  (none found)")

        if direction in ("callers", "both"):
            output_lines.append("\n── CALLERS (functions that call this) ──")
            caller_entries: list[str] = []
            _trace_callers(symbol, depth, visited, caller_entries, [1])
            if caller_entries:
                output_lines.extend(caller_entries)
            else:
                output_lines.append("  (none found)")

        result = "\n".join(output_lines)

        # Layer 1 (P0): Hard cap for trace responses.
        if len(result) > hard_cap:
            result = result[:hard_cap].rstrip()
            result += (
                "\n\n[Truncated: response exceeded size limit. "
                "Try reducing depth or adding a subsystem filter.]"
            )

        return result

    return await loop.run_in_executor(None, _run_trace)


# ---------------------------------------------------------------------------
# Tool: memory  (hybrid upsert into the dedicated notes collection)
# ---------------------------------------------------------------------------


@mcp.tool(name="memory", description=TOOL_MEMORY_DESCRIPTION)
async def memory(
    information: str,
    metadata: Optional[dict[str, Any]] = None,
) -> str:
    """
    Store information in the dedicated notes collection with both dense and
    sparse vectors so it is discoverable by hybrid search.

    Always writes to the notes collection (``NOTES_COLLECTION_NAME``) which
    is never touched by ``--recreate`` — agent memory is persistent.

    Parameters
    ----------
    information:
        Natural-language description of what is being stored.  This text
        is embedded and used as the primary search surface.
    metadata:
        Optional structured metadata (JSON-serialisable dict).  Stored
        in the point payload under the ``metadata`` key.
    """
    client = _get_client()
    emb_mgr = _get_embeddings()

    loop = asyncio.get_event_loop()

    # 0. Ensure notes collection exists with hybrid config.
    await _ensure_collection(client, NOTES_COLLECTION_NAME)

    # 1. Embed the information text (async → thread executor).
    emb = await emb_mgr.aembed_passages([information])
    if not emb:
        return "Error: embedding returned no results."
    hybrid = emb[0]

    # 2. Build the point.
    #
    # We use a random UUID rather than a deterministic one so that
    # storing the same text twice creates two separate memories (the
    # LLM may annotate the same concept differently across sessions).
    # If dedup is desired the caller can delete-and-re-store.
    point_id = uuid.uuid4().hex
    point = qmodels.PointStruct(
        id=point_id,
        vector={
            DENSE_VECTOR_NAME: hybrid.dense.values,
            SPARSE_VECTOR_NAME: hybrid.sparse.to_qdrant(),
        },
        payload={
            "type": "mcp_stored",
            "document": information,
            METADATA_PATH: metadata,
        },
    )

    # 3. Upsert (thread executor).
    def _upsert() -> None:
        client.upsert(collection_name=NOTES_COLLECTION_NAME, points=[point])

    await loop.run_in_executor(None, _upsert)

    logger.info("Stored point %s in notes collection '%s'.", point_id, NOTES_COLLECTION_NAME)
    return (
        f"Successfully stored information in notes collection "
        f"'{NOTES_COLLECTION_NAME}' (point {point_id})."
    )


# ---------------------------------------------------------------------------
# Tool: qdrant-reindex  (incremental re-indexing of the CrucibleOS repo)
# ---------------------------------------------------------------------------


@mcp.tool(name="qdrant-reindex", description=TOOL_REINDEX_DESCRIPTION)
async def qdrant_reindex(
    reindex_patterns: bool = False,
    collection_name: Optional[str] = None,
) -> str:
    """
    Incrementally re-index the CerberusOS codebase.

    Detects files that changed since the last index run (via BLAKE2s
    content hashing) and only re-embeds/upserts those.  Unchanged files
    are skipped.

    Parameters
    ----------
    reindex_patterns:
        If ``True``, also re-mine and upsert architecture patterns.
        Default ``False`` (faster — usually not needed for small edits).
    collection_name:
        Qdrant collection to index into (defaults to the configured
        ``COLLECTION_NAME``).
    """
    from cerberus_indexer.indexer import run_index

    coll = _resolve_collection(collection_name)
    repo_root = CERBERUS_REPO_ROOT.resolve()

    if not repo_root.is_dir():
        return f"Error: CRUCIBLE_REPO_ROOT '{repo_root}' is not a valid directory."

    loop = asyncio.get_event_loop()

    def _run() -> str:
        # Capture print() output from run_index for the summary.
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run_index(
                repo_root=repo_root,
                recreate=False,  # Never recreate from MCP — incremental only
                skip_code=False,
                skip_patterns=not reindex_patterns,
                collection_name=coll,
            )
        return buf.getvalue()

    try:
        output = await loop.run_in_executor(None, _run)
    except Exception as exc:
        logger.exception("qdrant-reindex failed")
        return f"Re-index failed: {str(exc)}"

    # Build a clean summary from the captured output.
    summary_lines = [line for line in output.strip().splitlines() if line.strip()]
    if summary_lines:
        return "Re-index complete:\n" + "\n".join(summary_lines)
    return "Re-index complete (no output captured — check server logs for details)."


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """
    Launch the hybrid MCP server.

    This is the ``cerberus-mcp-server`` (legacy: ``crucible-mcp-server``)
    console entry point defined in ``pyproject.toml``.  It delegates to FastMCP's built-in ``run()``
    which handles transport negotiation (stdio / sse / streamable-http)
    based on command-line flags.
    """
    # Configure logging — stderr only so stdout stays clean for MCP stdio.
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    # FastMCP's run() parses sys.argv for --transport, etc.
    mcp.run()


if __name__ == "__main__":
    main()
