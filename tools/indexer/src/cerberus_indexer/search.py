"""
Hybrid, dense-only, and sparse-only search against a Qdrant collection.

All three search modes share the same return type
(:class:`qdrant_client.http.models.ScoredPoint`) so callers can treat
results uniformly regardless of which retrieval strategy was used.

Hybrid search
~~~~~~~~~~~~~
The default and recommended mode.  It issues two ``Prefetch`` sub-queries
— one against the dense (MiniLM) vector and one against the sparse (BM25)
vector — then fuses the candidate sets with **Reciprocal Rank Fusion**
(RRF).  This gives the best of both worlds: semantic understanding *and*
exact keyword / symbol matching.

Dense-only
~~~~~~~~~~
Pure cosine-similarity search against the dense vector.  Good for broad
conceptual queries (e.g. "how does the kernel handle page faults").

Sparse-only
~~~~~~~~~~~
Pure BM25 keyword search against the sparse vector.  Good for exact
symbol names, capability IDs, function signatures, etc.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels

from cerberus_indexer.config import (
    COLLECTION_NAME,
    DENSE_VECTOR_NAME,
    HYBRID_DEFAULT_LIMIT,
    HYBRID_PREFETCH_LIMIT,
    METADATA_PATH,
    NOTES_COLLECTION_NAME,
    SPARSE_VECTOR_NAME,
)
from cerberus_indexer.embeddings import EmbeddingManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Filter builder (shared across all modes)
# ---------------------------------------------------------------------------


def _build_filter(
    type_filter: Optional[str] = None,
    file_filter: Optional[str] = None,
    subsystem: Optional[str] = None,
    crate: Optional[str] = None,
    kind: Optional[str] = None,
    symbols: Optional[List[str]] = None,
    exclude_tests: bool = False,
) -> Optional[qmodels.Filter]:
    """
    Build a Qdrant filter from optional constraints.

    Parameters
    ----------
    type_filter:
        If set, restrict results to points whose ``type`` payload field
        equals this value (e.g. ``"code_chunk"`` or ``"pattern"``).
    file_filter:
        If set, restrict results to points whose ``metadata.file``
        payload field contains this substring (full-text match).
    subsystem:
        If set, restrict to a specific Cerberus subsystem
        (``"kernel"``, ``"runtime"``, ``"crucibles"``, ``"crypto"``,
        ``"tools"``, ``"tests"``, ``"docs"``, ``"library"``).
    crate:
        If set, restrict to a specific crate name (e.g. ``"forge-boot"``).
    kind:
        If set, restrict to a structural kind
        (``"function"``, ``"impl"``, ``"struct"``, ``"enum"``, ``"trait"``,
        ``"module"``, ``"const"``, ``"test"``, ``"mixed"``).
    symbols:
        If set, restrict to chunks that define at least one of the given
        symbol names.
    exclude_tests:
        If ``True``, exclude chunks with ``metadata.is_test == True``.

    Returns
    -------
    Optional[qmodels.Filter]
        A ``Filter`` with ``must`` conditions, or ``None`` when no
        constraints were supplied.
    """
    conditions: List[qmodels.Condition] = []

    if type_filter:
        conditions.append(
            qmodels.FieldCondition(
                key="type",
                match=qmodels.MatchValue(value=type_filter),
            )
        )
    if file_filter:
        conditions.append(
            qmodels.FieldCondition(
                key=f"{METADATA_PATH}.file",
                match=qmodels.MatchText(text=file_filter),
            )
        )
    if subsystem:
        conditions.append(
            qmodels.FieldCondition(
                key=f"{METADATA_PATH}.subsystem",
                match=qmodels.MatchValue(value=subsystem),
            )
        )
    if crate:
        conditions.append(
            qmodels.FieldCondition(
                key=f"{METADATA_PATH}.crate",
                match=qmodels.MatchValue(value=crate),
            )
        )
    if kind:
        conditions.append(
            qmodels.FieldCondition(
                key=f"{METADATA_PATH}.kind",
                match=qmodels.MatchValue(value=kind),
            )
        )
    if symbols:
        for sym in symbols:
            if sym.strip():
                conditions.append(
                    qmodels.FieldCondition(
                        key=f"{METADATA_PATH}.declared",
                        match=qmodels.MatchValue(value=sym.strip()),
                    )
                )
    if exclude_tests:
        conditions.append(
            qmodels.FieldCondition(
                key=f"{METADATA_PATH}.is_test",
                match=qmodels.MatchValue(value=False),
            )
        )

    return qmodels.Filter(must=conditions) if conditions else None


# ---------------------------------------------------------------------------
# Hybrid search (dense + sparse → RRF fusion)
# ---------------------------------------------------------------------------


def hybrid_search(
    client: QdrantClient,
    embeddings: EmbeddingManager,
    query_text: str,
    collection_name: str = COLLECTION_NAME,
    limit: int = HYBRID_DEFAULT_LIMIT,
    prefetch_limit: int = HYBRID_PREFETCH_LIMIT,
    type_filter: Optional[str] = None,
    file_filter: Optional[str] = None,
    subsystem: Optional[str] = None,
    crate: Optional[str] = None,
    kind: Optional[str] = None,
    symbols: Optional[List[str]] = None,
    exclude_tests: bool = False,
) -> List[qmodels.ScoredPoint]:
    """
    Perform hybrid search combining dense (semantic) and sparse (BM25
    keyword) retrieval with Reciprocal Rank Fusion (RRF).

    Query flow
    ----------
    1. Embed the query with both dense and sparse models.
    2. Issue two ``Prefetch`` sub-queries (one per vector space), each
       retrieving up to *prefetch_limit* candidates.
    3. Fuse the two candidate lists via RRF for the final ranking.

    Parameters
    ----------
    client:
        Connected Qdrant client.
    embeddings:
        Initialised :class:`EmbeddingManager`.
    query_text:
        Natural-language query string.
    collection_name:
        Qdrant collection to search.
    limit:
        Number of final results to return after fusion.
    prefetch_limit:
        Number of candidates each leg fetches before fusion.
    type_filter:
        Optional payload ``type`` filter.
    file_filter:
        Optional ``metadata.file`` substring filter.
    subsystem:
        Optional subsystem filter (``"kernel"``, ``"runtime"``, etc.).
    crate:
        Optional crate name filter.
    kind:
        Optional structural kind filter.
    symbols:
        Optional list of symbol names to filter on.
    exclude_tests:
        If ``True``, exclude test chunks.

    Returns
    -------
    List[qmodels.ScoredPoint]
        Fused results with payloads attached.
    """
    emb = embeddings.embed_query(query_text)
    search_filter = _build_filter(
        type_filter, file_filter, subsystem, crate, kind, symbols, exclude_tests
    )

    prefetches = [
        # Leg 1: dense (semantic) search
        qmodels.Prefetch(
            query=emb.dense.values,
            using=DENSE_VECTOR_NAME,
            limit=prefetch_limit,
            filter=search_filter,
        ),
        # Leg 2: sparse (BM25 keyword) search
        qmodels.Prefetch(
            query=emb.sparse.to_qdrant(),
            using=SPARSE_VECTOR_NAME,
            limit=prefetch_limit,
            filter=search_filter,
        ),
    ]

    results = client.query_points(
        collection_name=collection_name,
        prefetch=prefetches,
        query=qmodels.FusionQuery(fusion=qmodels.Fusion.RRF),
        limit=limit,
        with_payload=True,
    )

    logger.debug(
        "hybrid_search(%r) → %d results (collection=%s)",
        query_text,
        len(results.points),
        collection_name,
    )
    return results.points


# ---------------------------------------------------------------------------
# Dense-only search
# ---------------------------------------------------------------------------


def dense_search(
    client: QdrantClient,
    embeddings: EmbeddingManager,
    query_text: str,
    collection_name: str = COLLECTION_NAME,
    limit: int = HYBRID_DEFAULT_LIMIT,
    type_filter: Optional[str] = None,
    file_filter: Optional[str] = None,
    subsystem: Optional[str] = None,
    crate: Optional[str] = None,
    kind: Optional[str] = None,
    symbols: Optional[List[str]] = None,
    exclude_tests: bool = False,
) -> List[qmodels.ScoredPoint]:
    """
    Search using only the dense (semantic / cosine) vector.

    Parameters are a subset of :func:`hybrid_search`; see that function
    for full documentation.
    """
    emb = embeddings.embed_query_dense_only(query_text)
    search_filter = _build_filter(
        type_filter, file_filter, subsystem, crate, kind, symbols, exclude_tests
    )

    results = client.query_points(
        collection_name=collection_name,
        query=emb.values,
        using=DENSE_VECTOR_NAME,
        limit=limit,
        with_payload=True,
        query_filter=search_filter,
    )

    logger.debug(
        "dense_search(%r) → %d results (collection=%s)",
        query_text,
        len(results.points),
        collection_name,
    )
    return results.points


# ---------------------------------------------------------------------------
# Sparse-only search
# ---------------------------------------------------------------------------


def sparse_search(
    client: QdrantClient,
    embeddings: EmbeddingManager,
    query_text: str,
    collection_name: str = COLLECTION_NAME,
    limit: int = HYBRID_DEFAULT_LIMIT,
    type_filter: Optional[str] = None,
    file_filter: Optional[str] = None,
    subsystem: Optional[str] = None,
    crate: Optional[str] = None,
    kind: Optional[str] = None,
    symbols: Optional[List[str]] = None,
    exclude_tests: bool = False,
) -> List[qmodels.ScoredPoint]:
    """
    Search using only the sparse (BM25 keyword) vector.

    Parameters are a subset of :func:`hybrid_search`; see that function
    for full documentation.
    """
    emb = embeddings.embed_query_sparse_only(query_text)
    search_filter = _build_filter(
        type_filter, file_filter, subsystem, crate, kind, symbols, exclude_tests
    )

    results = client.query_points(
        collection_name=collection_name,
        query=emb.to_qdrant(),
        using=SPARSE_VECTOR_NAME,
        limit=limit,
        with_payload=True,
        query_filter=search_filter,
    )

    logger.debug(
        "sparse_search(%r) → %d results (collection=%s)",
        query_text,
        len(results.points),
        collection_name,
    )
    return results.points


# ---------------------------------------------------------------------------
# Async wrappers (for the MCP server)
# ---------------------------------------------------------------------------


async def ahybrid_search(
    client: QdrantClient,
    embeddings: EmbeddingManager,
    query_text: str,
    collection_name: str = COLLECTION_NAME,
    limit: int = HYBRID_DEFAULT_LIMIT,
    prefetch_limit: int = HYBRID_PREFETCH_LIMIT,
    type_filter: Optional[str] = None,
    file_filter: Optional[str] = None,
    subsystem: Optional[str] = None,
    crate: Optional[str] = None,
    kind: Optional[str] = None,
    symbols: Optional[List[str]] = None,
    exclude_tests: bool = False,
) -> List[qmodels.ScoredPoint]:
    """
    Async hybrid search.

    Embeds the query asynchronously (via a thread executor), then issues
    the Qdrant query synchronously (qdrant-client is not fully async in
    all configurations, and the network call is fast relative to
    embedding).
    """
    import asyncio

    loop = asyncio.get_event_loop()
    emb = await embeddings.aembed_query(query_text)
    search_filter = _build_filter(
        type_filter, file_filter, subsystem, crate, kind, symbols, exclude_tests
    )

    prefetches = [
        qmodels.Prefetch(
            query=emb.dense.values,
            using=DENSE_VECTOR_NAME,
            limit=prefetch_limit,
            filter=search_filter,
        ),
        qmodels.Prefetch(
            query=emb.sparse.to_qdrant(),
            using=SPARSE_VECTOR_NAME,
            limit=prefetch_limit,
            filter=search_filter,
        ),
    ]

    def _query() -> List[qmodels.ScoredPoint]:
        results = client.query_points(
            collection_name=collection_name,
            prefetch=prefetches,
            query=qmodels.FusionQuery(fusion=qmodels.Fusion.RRF),
            limit=limit,
            with_payload=True,
        )
        return results.points

    return await loop.run_in_executor(None, _query)


# ---------------------------------------------------------------------------
# Cross-collection search (code + notes → merged RRF)
# ---------------------------------------------------------------------------


def _rrf_merge(
    lists: list[list[qmodels.ScoredPoint]],
    limit: int,
    k: int = 60,
) -> list[qmodels.ScoredPoint]:
    """
    Merge multiple ranked result lists with Reciprocal Rank Fusion (RRF).

    Parameters
    ----------
    lists:
        One list of :class:`ScoredPoint` per source (already ranked).
    limit:
        Maximum number of merged results to return.
    k:
        RRF smoothing constant (default 60 — standard value).

    Returns
    -------
    List of :class:`ScoredPoint` sorted by descending RRF score.
    The ``.score`` attribute on each point is replaced with the RRF score
    so callers can treat results uniformly.
    """
    scores: dict[str, float] = {}
    points_by_id: dict[str, qmodels.ScoredPoint] = {}

    for ranked_list in lists:
        for rank, pt in enumerate(ranked_list, 1):
            pid = str(pt.id)
            scores[pid] = scores.get(pid, 0.0) + 1.0 / (k + rank)
            if pid not in points_by_id:
                points_by_id[pid] = pt

    sorted_ids = sorted(scores, key=lambda x: scores[x], reverse=True)[:limit]
    result = []
    for pid in sorted_ids:
        pt = points_by_id[pid]
        # Replace score with the RRF score.
        result.append(
            qmodels.ScoredPoint(
                id=pt.id,
                version=pt.version,
                score=scores[pid],
                payload=pt.payload,
                vector=pt.vector,
            )
        )
    return result


def merged_hybrid_search(
    client: QdrantClient,
    embeddings: EmbeddingManager,
    query_text: str,
    code_collection: str = COLLECTION_NAME,
    notes_collection: str = NOTES_COLLECTION_NAME,
    limit: int = HYBRID_DEFAULT_LIMIT,
    prefetch_limit: int = HYBRID_PREFETCH_LIMIT,
    type_filter: Optional[str] = None,
    file_filter: Optional[str] = None,
    subsystem: Optional[str] = None,
    crate: Optional[str] = None,
    kind: Optional[str] = None,
    symbols: Optional[List[str]] = None,
    exclude_tests: bool = False,
) -> List[qmodels.ScoredPoint]:
    """
    Hybrid search across *both* the code collection and the notes collection.

    Issues hybrid RRF queries against each collection independently, then
    merges the two result lists with a second RRF pass so the final ranking
    reflects signal from both collections.

    If *notes_collection* does not exist (e.g. fresh install before any
    ``memory`` calls), the function gracefully returns only code results
    without raising an error.
    """
    code_results = hybrid_search(
        client=client,
        embeddings=embeddings,
        query_text=query_text,
        collection_name=code_collection,
        limit=limit,
        prefetch_limit=prefetch_limit,
        type_filter=type_filter,
        file_filter=file_filter,
        subsystem=subsystem,
        crate=crate,
        kind=kind,
        symbols=symbols,
        exclude_tests=exclude_tests,
    )

    notes_results: List[qmodels.ScoredPoint] = []
    if client.collection_exists(notes_collection):
        try:
            notes_results = hybrid_search(
                client=client,
                embeddings=embeddings,
                query_text=query_text,
                collection_name=notes_collection,
                limit=limit,
                prefetch_limit=prefetch_limit,
            )
        except Exception:
            logger.warning(
                "Failed to search notes collection '%s'; skipping.",
                notes_collection,
                exc_info=True,
            )

    if not notes_results:
        return code_results[:limit]

    merged = _rrf_merge([code_results, notes_results], limit=limit)
    logger.debug(
        "merged_hybrid_search(%r) → %d results (code=%d, notes=%d)",
        query_text,
        len(merged),
        len(code_results),
        len(notes_results),
    )
    return merged


def format_result(point: qmodels.ScoredPoint, rank: int = 1) -> str:
    """
    Format a single :class:`ScoredPoint` as a human-readable string.

    Used by both the CLI ``--query`` mode and the MCP server's
    ``crucible-search`` tool response.
    """
    payload = point.payload or {}
    ptype = payload.get("type", "?")
    score = point.score

    if ptype == "code_chunk":
        meta = payload.get(METADATA_PATH, {}) or {}
        file_path = meta.get("file", "?")
        chunk_idx = meta.get("chunk_index", "?")
        total = meta.get("total_chunks", "?")
        lang = meta.get("language", "?")
        doc = payload.get("document", "")
        preview = (doc[:140] + "…") if len(doc) > 140 else doc
        return (
            f"  {rank}. [{score:.4f}] {file_path} "
            f"(chunk {chunk_idx}/{total}, {lang})\n"
            f"     {preview}"
        )

    if ptype == "pattern":
        name = payload.get("pattern_name", "?")
        reason = payload.get("reason", "")
        tags = payload.get("tags", [])
        n_ev = len(payload.get("evidence", []))
        return (
            f"  {rank}. [{score:.4f}] PATTERN: {name}\n"
            f"     Reason: {reason}\n"
            f"     Tags: {', '.join(tags)} | Evidence: {n_ev} hits"
        )

    if ptype == "mcp_stored":
        doc = payload.get("document", "")
        preview = (doc[:140] + "…") if len(doc) > 140 else doc
        return f"  {rank}. [{score:.4f}] STORED: {preview}"

    return f"  {rank}. [{score:.4f}] type={ptype}"


def format_results(points: List[qmodels.ScoredPoint]) -> str:
    """
    Format a full result list as a human-readable multi-line string.

    Returns ``"  (no results)"`` when *points* is empty.
    """
    if not points:
        return "  (no results)"
    lines: List[str] = []
    for i, pt in enumerate(points, 1):
        lines.append(format_result(pt, rank=i))
    return "\n\n".join(lines)
