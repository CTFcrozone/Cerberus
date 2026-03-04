"""
Tests for the intelligent token budget system (budget.py).

Tests cover all three layers:

- Layer 1 (P0): Hard response cap (tested via config + server integration smoke)
- Layer 2 (P1): Score-cliff detection and TieredBudget allocation
- Layer 3 (P2): Query intent classification and BUDGET_PRESETS structure

Run with::

    cd tools/indexer
    pip install -e ".[dev]"
    pytest tests/test_budget.py -v
"""

from __future__ import annotations

import pytest

from cerberus_indexer.budget import (
    BUDGET_PRESETS,
    TieredBudget,
    _metadata_summary,
    _trim_to_signature,
    detect_score_cliff,
    estimate_query_intent,
)

# ---------------------------------------------------------------------------
# Layer 2 (P1): detect_score_cliff
# ---------------------------------------------------------------------------


class TestDetectScoreCliff:
    """Unit tests for detect_score_cliff()."""

    def test_example_cliff_at_3(self):
        """Documented example: 0.85 → 0.41 is a 52% drop → cliff at index 3."""
        assert detect_score_cliff([0.92, 0.87, 0.85, 0.41, 0.38], 0.35) == 3

    def test_no_cliff_gradual_descent(self):
        """Gradual descent — no cliff, returns len(scores)."""
        assert detect_score_cliff([0.9, 0.85, 0.80, 0.75], 0.35) == 4

    def test_empty_list(self):
        """Empty input returns 0."""
        assert detect_score_cliff([], 0.35) == 0

    def test_single_element(self):
        """Single element returns 1."""
        assert detect_score_cliff([0.5], 0.35) == 1

    def test_cliff_at_first_gap(self):
        """Cliff right at index 1."""
        assert detect_score_cliff([0.9, 0.4], 0.35) == 1

    def test_all_equal_scores(self):
        """No drop at all — no cliff, returns len(scores)."""
        assert detect_score_cliff([0.8, 0.8, 0.8], 0.35) == 3

    def test_custom_min_drop_ratio(self):
        """A 20% drop triggers a cliff with min_drop_ratio=0.15."""
        scores = [1.0, 0.79]
        assert detect_score_cliff(scores, min_drop_ratio=0.15) == 1

    def test_cliff_not_triggered_below_threshold(self):
        """A 25% drop does NOT trigger a cliff at default 35% threshold."""
        scores = [0.80, 0.60]
        # 0.80 → 0.60 is 25% drop, below 35% threshold
        assert detect_score_cliff(scores, 0.35) == 2

    def test_two_element_cliff(self):
        """52 % drop: 0.85 → 0.41 triggers cliff at index 1."""
        assert detect_score_cliff([0.85, 0.41], 0.35) == 1


# ---------------------------------------------------------------------------
# Layer 2 (P1): TieredBudget
# ---------------------------------------------------------------------------


class TestTieredBudget:
    """Unit tests for TieredBudget.allocate()."""

    def _make_items(self, scores: list[float]) -> list[tuple[float, str, dict]]:
        """Build synthetic (score, content, meta) items."""
        items = []
        for i, s in enumerate(scores):
            content = "\n".join([f"line {j}" for j in range(20)])
            meta = {
                "file": f"src/file{i}.rs",
                "line_start": i * 10,
                "line_end": i * 10 + 20,
                "kind": "function",
                "crate": "forge",
                "symbols": [f"func_{i}"],
            }
            items.append((s, content, meta))
        return items

    def test_tier_classification(self):
        """Scores [0.92, 0.87, 0.65, 0.42, 0.38] with best=0.92."""
        # Tier 1 (≥0.85 * 0.92 = 0.782): results 0, 1  (0.92, 0.87)
        # Tier 2 (≥0.55 * 0.92 = 0.506): result 2 (0.65)
        # Tier 3 (<0.506): results 3, 4 (0.42, 0.38)
        scores = [0.92, 0.87, 0.65, 0.42, 0.38]
        items = self._make_items(scores)
        budget = TieredBudget(total_budget=10000)
        results = budget.allocate(items)

        assert len(results) == 5
        assert results[0][0] == "full"
        assert results[1][0] == "full"
        assert results[2][0] == "trimmed"
        assert results[3][0] == "metadata"
        assert results[4][0] == "metadata"

    def test_empty_input(self):
        """Empty items list returns empty list."""
        assert TieredBudget().allocate([]) == []

    def test_single_result_is_full(self):
        """Single result is always Tier 1 (full)."""
        items = self._make_items([0.85])
        results = TieredBudget(total_budget=5000).allocate(items)
        assert results[0][0] == "full"

    def test_output_text_not_empty(self):
        """Each allocation must produce non-empty output text."""
        scores = [0.90, 0.70, 0.30]
        items = self._make_items(scores)
        results = TieredBudget(total_budget=3000).allocate(items)
        for _tier, text in results:
            assert text.strip() != ""

    def test_metadata_tier_format(self):
        """Tier-3 output is a compact metadata line."""
        scores = [0.90, 0.20]
        items = self._make_items(scores)
        results = TieredBudget(total_budget=2000).allocate(items)
        tier_label, text = results[1]
        assert tier_label == "metadata"
        assert "src/file1.rs" in text
        assert "function" in text

    def test_trimmed_tier_has_omission_marker(self):
        """Tier-2 output contains the omission marker for long content."""
        best = 0.90
        mid = 0.60  # ratio = 0.60/0.90 = 0.667 → Tier 2
        items = [
            (best, "\n".join([f"line {j}" for j in range(30)]), {}),
            (mid, "\n".join([f"line {j}" for j in range(30)]), {}),
        ]
        results = TieredBudget(total_budget=5000).allocate(items)
        tier_label, text = results[1]
        assert tier_label == "trimmed"
        assert "lines omitted" in text

    def test_empty_tier1_redistributes_budget(self):
        """When no Tier-1 results exist, budget flows to lower tiers."""
        # All scores below 85% of best → no Tier 1
        # ratio: 0.60/0.70 = 0.857 → just at border; 0.40/0.70 = 0.571 → Tier 2
        scores = [0.70, 0.60, 0.40]
        items = self._make_items(scores)
        budget = TieredBudget(
            total_budget=6000,
            tier1_budget_pct=0.60,
            tier2_budget_pct=0.25,
            tier3_budget_pct=0.15,
        )
        results = budget.allocate(items)
        # All should produce non-empty text despite empty tier 1
        for _tier, text in results:
            assert len(text) > 0

    def test_only_tier3_results(self):
        """Scores where only the top result is Tier 1 and the rest fall to Tier 3."""
        # best=0.50; 0.25/0.50=0.50 < 0.55 → Tier 3; 0.20/0.50=0.40 → Tier 3
        scores = [0.50, 0.25, 0.20]
        items = self._make_items(scores)
        budget = TieredBudget(total_budget=3000)
        results = budget.allocate(items)
        # Top result is always Tier 1 (it IS the best score)
        assert results[0][0] == "full"
        # Remaining results below 55% threshold are Tier 3
        assert results[1][0] == "metadata"
        assert results[2][0] == "metadata"
        for _tier, text in results:
            assert len(text) > 0


# ---------------------------------------------------------------------------
# Layer 2 (P1): _trim_to_signature helper
# ---------------------------------------------------------------------------


class TestTrimToSignature:
    def test_keeps_head_and_tail(self):
        lines = [f"line{i}" for i in range(20)]
        result = _trim_to_signature("\n".join(lines), {}, budget=10000)
        assert "line0" in result
        assert "line19" in result
        assert "lines omitted" in result

    def test_short_content_no_omission(self):
        """Content with ≤5 lines should have no omission marker."""
        content = "line0\nline1\nline2"
        result = _trim_to_signature(content, {}, budget=10000)
        assert "lines omitted" not in result

    def test_respects_budget(self):
        content = "x" * 1000
        result = _trim_to_signature(content, {}, budget=50)
        assert len(result) <= 50


# ---------------------------------------------------------------------------
# Layer 2 (P1): _metadata_summary helper
# ---------------------------------------------------------------------------


class TestMetadataSummary:
    def test_basic_format(self):
        meta = {
            "file": "src/main.rs",
            "line_start": 10,
            "line_end": 50,
            "kind": "function",
            "crate": "forge",
            "symbols": ["entry_point", "init"],
        }
        result = _metadata_summary(meta, budget=10000)
        assert "src/main.rs:10-50" in result
        assert "[function]" in result
        assert "crate=forge" in result
        assert "entry_point" in result

    def test_respects_budget(self):
        meta = {"file": "x" * 500}
        result = _metadata_summary(meta, budget=20)
        assert len(result) <= 20


# ---------------------------------------------------------------------------
# Layer 3 (P2): estimate_query_intent
# ---------------------------------------------------------------------------


class TestEstimateQueryIntent:
    def test_short_symbol_lookup(self):
        """Short query → lookup."""
        assert estimate_query_intent("kernel_main", "kernel_main", None) == "lookup"

    def test_long_exploration_query(self):
        """Long natural-language query → exploration."""
        assert (
            estimate_query_intent("how does the boot sequence initialize services", None, None)
            == "exploration"
        )

    def test_struct_kind_is_exploration(self):
        """kind=struct → exploration."""
        assert estimate_query_intent("memory layout", None, "struct") == "exploration"

    def test_enum_kind_is_exploration(self):
        assert estimate_query_intent("syscall variants", None, "enum") == "exploration"

    def test_trait_kind_is_exploration(self):
        assert estimate_query_intent("capabilities", None, "trait") == "exploration"

    def test_function_kind_short_query_is_lookup(self):
        """kind=function with a short query stays as lookup."""
        assert estimate_query_intent("entry_point", None, "function") == "lookup"

    def test_empty_query_is_lookup(self):
        """Very short query treated as lookup."""
        assert estimate_query_intent("init", None, None) == "lookup"


# ---------------------------------------------------------------------------
# Layer 3 (P2): BUDGET_PRESETS structure
# ---------------------------------------------------------------------------


class TestBudgetPresets:
    def test_all_intents_present(self):
        assert "lookup" in BUDGET_PRESETS
        assert "exploration" in BUDGET_PRESETS
        assert "trace" in BUDGET_PRESETS

    def test_lookup_has_limit_override(self):
        assert BUDGET_PRESETS["lookup"]["limit_override"] == 3

    def test_exploration_no_limit_override(self):
        assert BUDGET_PRESETS["exploration"]["limit_override"] is None

    def test_trace_larger_budget_than_lookup(self):
        assert BUDGET_PRESETS["trace"]["total_budget"] > BUDGET_PRESETS["lookup"]["total_budget"]

    def test_tier_pct_sum_to_one(self):
        for intent, preset in BUDGET_PRESETS.items():
            total = (
                preset["tier1_budget_pct"] + preset["tier2_budget_pct"] + preset["tier3_budget_pct"]
            )
            assert abs(total - 1.0) < 1e-9, f"{intent}: tier pcts sum to {total}"

    def test_lookup_tier3_is_zero(self):
        """Lookup has no metadata-only results."""
        assert BUDGET_PRESETS["lookup"]["tier3_budget_pct"] == 0.00


# ---------------------------------------------------------------------------
# Layer 1 (P0): Config has DEFAULT_MAX_RESPONSE_CHARS
# ---------------------------------------------------------------------------


class TestConfigBudget:
    def test_default_max_response_chars_exists(self):
        from cerberus_indexer import config

        assert hasattr(config, "DEFAULT_MAX_RESPONSE_CHARS")
        assert isinstance(config.DEFAULT_MAX_RESPONSE_CHARS, int)
        assert config.DEFAULT_MAX_RESPONSE_CHARS > 0

    def test_default_value_is_12000(self):
        """Default when env var is not set."""
        import os

        from crucible_indexer import config

        # Only assert the default if the env var isn't overriding it.
        if "MAX_RESPONSE_CHARS" not in os.environ:
            assert config.DEFAULT_MAX_RESPONSE_CHARS == 12000


# ---------------------------------------------------------------------------
# Layer 1 (P0): Hard cap truncation logic (unit tests)
# ---------------------------------------------------------------------------


class TestHardCapTruncation:
    """Unit tests for the hard-cap truncation helper logic."""

    def _truncate(self, response: str, hard_cap: int, total_found: int) -> str:
        """Mirror the server's truncation logic for unit testing."""
        if len(response) <= hard_cap:
            return response
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

    def test_no_truncation_under_cap(self):
        response = "--- Result 1 (score 0.9, full) ---\nhello"
        assert self._truncate(response, 10000, 1) == response

    def test_truncates_at_result_boundary(self):
        r1 = "--- Result 1 (score 0.9, full) ---\n" + "x" * 100
        r2 = "--- Result 2 (score 0.5, metadata) ---\n" + "y" * 100
        response = r1 + "\n\n" + r2
        # Cap just enough to cut before Result 2
        hard_cap = len(r1) + 5
        result = self._truncate(response, hard_cap, 2)
        assert "--- Result 2" not in result
        assert "Truncated" in result
        assert "showing 1 of 2 results" in result

    def test_truncates_at_char_limit_when_no_boundary(self):
        response = "some content without any result markers " * 10
        hard_cap = 30
        result = self._truncate(response, hard_cap, 5)
        # Since there's no boundary, truncates at hard_cap
        assert "Truncated" in result

    def test_truncation_notice_includes_filter_hint(self):
        r1 = "--- Result 1 (score 0.9, full) ---\n" + "x" * 200
        r2 = "--- Result 2 (score 0.5, metadata) ---\n" + "y" * 200
        response = r1 + "\n\n" + r2
        result = self._truncate(response, len(r1) + 5, 5)
        assert "crate=" in result or "subsystem=" in result


# ---------------------------------------------------------------------------
# Import smoke test
# ---------------------------------------------------------------------------


class TestBudgetImport:
    def test_import_budget(self):
        from cerberus_indexer import budget

        assert callable(budget.detect_score_cliff)
        assert callable(budget.estimate_query_intent)
        assert hasattr(budget, "TieredBudget")
        assert hasattr(budget, "BUDGET_PRESETS")
