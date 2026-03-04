"""
Intelligent token budget system for MCP server responses.

Three-layer system to prevent context-window overflows:

- Layer 1 (P0): Hard response cap with clean truncation at ``--- Result``
  boundaries. Enabled via ``DEFAULT_MAX_RESPONSE_CHARS`` / ``max_response_chars``.
- Layer 2 (P1): Score-cliff detection + tiered budget allocation (full /
  trimmed / metadata-only) based on RRF score relative to the best result.
- Layer 3 (P2): Query intent classification (``"lookup"`` / ``"exploration"``
  / ``"trace"``) that selects a preset budget configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Layer 2 (P1): Score-cliff detection
# ---------------------------------------------------------------------------


def detect_score_cliff(scores: list[float], min_drop_ratio: float = 0.35) -> int:
    """
    Find the index at which relevance scores drop off a cliff.

    A *cliff* is the first position where the score drops by more than
    *min_drop_ratio* (35 % by default) relative to the **previous** score.
    Results at that index and beyond should be demoted or dropped.

    Parameters
    ----------
    scores:
        Ordered list of RRF scores, highest first.
    min_drop_ratio:
        Minimum fractional drop (0 < ratio ≤ 1) that constitutes a cliff.

    Returns
    -------
    int
        Index of the first result *below* the cliff.  If no cliff is
        found (gradual descent), returns ``len(scores)`` — meaning all
        results are above the cliff.  Returns ``0`` for empty input,
        ``1`` for single-element input.

    Examples
    --------
    >>> detect_score_cliff([0.92, 0.87, 0.85, 0.41, 0.38], 0.35)
    3
    >>> detect_score_cliff([0.9, 0.85, 0.80, 0.75], 0.35)
    4
    >>> detect_score_cliff([], 0.35)
    0
    >>> detect_score_cliff([0.5], 0.35)
    1
    """
    if not scores:
        return 0
    if len(scores) == 1:
        return 1

    for i in range(1, len(scores)):
        prev = scores[i - 1]
        curr = scores[i]
        if prev == 0:
            # Avoid division by zero; treat as cliff if curr is also 0.
            if curr == 0:
                return i
            continue
        drop_ratio = (prev - curr) / prev
        if drop_ratio > min_drop_ratio:
            return i

    return len(scores)


# ---------------------------------------------------------------------------
# Layer 2 (P1): Tiered budget helpers
# ---------------------------------------------------------------------------


def _trim_to_signature(content: str, meta: dict[str, Any], budget: int) -> str:
    """
    Return the function signature + first 5 lines + last 3 lines of *content*.

    An omission marker is inserted between the header and tail sections.
    The result is capped to *budget* characters.
    """
    lines = content.splitlines()
    head = lines[:5]
    tail = lines[-3:] if len(lines) > 5 else []
    omitted = max(0, len(lines) - len(head) - len(tail))

    parts = list(head)
    if omitted > 0:
        parts.append(f"// ... ({omitted} lines omitted)")
    parts.extend(tail)

    result = "\n".join(parts)
    return result[:budget]


def _metadata_summary(meta: dict[str, Any], budget: int) -> str:
    """
    Format a compact metadata-only summary for a result.

    Includes: file path, line range, kind, crate, and symbols list.
    The result is capped to *budget* characters.
    """
    file_p = meta.get("file", "?")
    line_s = meta.get("line_start", "?")
    line_e = meta.get("line_end", "?")
    kind = meta.get("kind", "?")
    crate = meta.get("crate", "?")
    syms = meta.get("symbols", [])
    syms_str = ", ".join(syms) if syms else ""
    result = f"{file_p}:{line_s}-{line_e} [{kind}] crate={crate} symbols=[{syms_str}]"
    return result[:budget]


# ---------------------------------------------------------------------------
# Layer 2 (P1): TieredBudget
# ---------------------------------------------------------------------------


@dataclass
class TieredBudget:
    """
    Allocate a character budget across search results in three tiers.

    Tier 1 (full):
        Results scoring ≥ 85 % of the best score.  Full code content.
    Tier 2 (trimmed):
        Results scoring 55–85 % of the best score.  Signature + head/tail.
    Tier 3 (metadata):
        Results scoring < 55 % of the best score.  File, symbols, range only.

    Parameters
    ----------
    total_budget:
        Total character budget for all results combined.
    tier1_budget_pct:
        Fraction of *total_budget* allocated to Tier-1 results.
    tier2_budget_pct:
        Fraction of *total_budget* allocated to Tier-2 results.
    tier3_budget_pct:
        Fraction of *total_budget* allocated to Tier-3 results.
    """

    total_budget: int = 12000
    tier1_budget_pct: float = 0.60
    tier2_budget_pct: float = 0.25
    tier3_budget_pct: float = 0.15

    # Tier thresholds (relative to best score).
    _TIER1_THRESHOLD: float = field(default=0.85, init=False, repr=False)
    _TIER2_THRESHOLD: float = field(default=0.55, init=False, repr=False)

    def allocate(
        self,
        items: list[tuple[float, str, dict[str, Any]]],
    ) -> list[tuple[str, str]]:
        """
        Allocate budget across *items* and return tiered output texts.

        Parameters
        ----------
        items:
            List of ``(score, formatted_content, metadata_dict)`` tuples,
            ordered by descending score.

        Returns
        -------
        list[tuple[str, str]]
            List of ``(tier_label, output_text)`` tuples in the same order
            as *items*.  ``tier_label`` is one of ``"full"``, ``"trimmed"``,
            or ``"metadata"``.
        """
        if not items:
            return []

        best_score = items[0][0] if items else 1.0
        if best_score <= 0:
            best_score = 1.0

        # Categorise items into tiers.
        tier1: list[int] = []
        tier2: list[int] = []
        tier3: list[int] = []
        for idx, (score, _content, _meta) in enumerate(items):
            ratio = score / best_score
            if ratio >= self._TIER1_THRESHOLD:
                tier1.append(idx)
            elif ratio >= self._TIER2_THRESHOLD:
                tier2.append(idx)
            else:
                tier3.append(idx)

        # Per-item budgets within each tier.
        t1_budget = int(self.total_budget * self.tier1_budget_pct)
        t2_budget = int(self.total_budget * self.tier2_budget_pct)
        t3_budget = int(self.total_budget * self.tier3_budget_pct)

        t1_per = (t1_budget // len(tier1)) if tier1 else 0
        t2_per = (t2_budget // len(tier2)) if tier2 else 0
        t3_per = (t3_budget // len(tier3)) if tier3 else 0

        # Reallocate unused budgets when a tier is empty.
        if not tier1:
            leftover = t1_budget
            if tier2:
                t2_per += leftover // len(tier2)
            elif tier3:
                t3_per += leftover // len(tier3)
        if not tier2:
            leftover = t2_budget
            if tier1:
                t1_per += leftover // len(tier1)
            elif tier3:
                t3_per += leftover // len(tier3)
        if not tier3:
            leftover = t3_budget
            if tier1:
                t1_per += leftover // len(tier1)
            elif tier2:
                t2_per += leftover // len(tier2)

        results: list[tuple[str, str]] = [("", "")] * len(items)

        for idx in tier1:
            _score, content, _meta = items[idx]
            results[idx] = ("full", content[:t1_per] if t1_per else content)

        for idx in tier2:
            _score, content, meta = items[idx]
            results[idx] = ("trimmed", _trim_to_signature(content, meta, t2_per))

        for idx in tier3:
            _score, _content, meta = items[idx]
            results[idx] = ("metadata", _metadata_summary(meta, t3_per))

        return results


# ---------------------------------------------------------------------------
# Layer 3 (P2): Query intent classification
# ---------------------------------------------------------------------------

# Words that signal a natural-language question → "exploration" intent.
_QUESTION_WORDS: frozenset[str] = frozenset(
    {"how", "what", "why", "when", "where", "which", "who", "does", "is", "are"}
)


def estimate_query_intent(
    query: str,
    symbols: Optional[str],
    kind: Optional[str],
) -> str:
    """
    Classify the agent's query into an intent category.

    Parameters
    ----------
    query:
        The natural-language (or symbol-name) query string.
    symbols:
        Comma-separated symbol filter string passed to ``crucible-search``,
        or ``None``.
    kind:
        Structural kind filter (``"struct"``, ``"enum"``, ``"trait"``, …),
        or ``None``.

    Returns
    -------
    str
        One of:

        ``"lookup"``
            Direct symbol lookup — short query or ≤ 2 symbols specified.
        ``"exploration"``
            Conceptual investigation — long natural-language query or
            kind filter for struct / enum / trait.
        ``"trace"``
            Reserved for the ``trace`` tool; not returned by this function.
    """
    # Exploration: kind filter suggests browsing types, not looking up a symbol.
    exploration_kinds = {"struct", "enum", "trait", "impl", "module"}
    if kind and kind.lower() in exploration_kinds:
        return "exploration"

    # Count symbols supplied.
    sym_count = 0
    if symbols:
        sym_count = len([s for s in symbols.split(",") if s.strip()])

    # Lookup: very short query (≤ 3 words) or direct symbol reference.
    words = query.split()
    if len(words) <= 3 or sym_count <= 2:
        # Treat as lookup only when query looks like a symbol name or is short.
        if len(words) <= 3:
            return "lookup"

    # Exploration: natural-language question (starts with interrogative word).
    first_word = words[0].lower().rstrip("?") if words else ""
    if first_word in _QUESTION_WORDS:
        return "exploration"

    # Exploration: long natural-language query.
    if len(words) > 8:
        return "exploration"

    # Default: lookup for medium-length queries with no exploration signals.
    return "lookup"


# ---------------------------------------------------------------------------
# Layer 3 (P2): Budget presets
# ---------------------------------------------------------------------------

BUDGET_PRESETS: dict[str, dict] = {
    "lookup": {
        "total_budget": 6000,
        "limit_override": 3,
        "tier1_budget_pct": 0.90,
        "tier2_budget_pct": 0.10,
        "tier3_budget_pct": 0.00,
    },
    "exploration": {
        "total_budget": 12000,
        "limit_override": None,
        "tier1_budget_pct": 0.60,
        "tier2_budget_pct": 0.25,
        "tier3_budget_pct": 0.15,
    },
    "trace": {
        "total_budget": 16000,
        "limit_override": None,
        "tier1_budget_pct": 0.50,
        "tier2_budget_pct": 0.30,
        "tier3_budget_pct": 0.20,
    },
}
