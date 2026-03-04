"""
Smoke tests for cerberus-indexer modules.

These tests verify that the core modules import cleanly and that the
pure-logic utilities (hashing, chunking, deterministic IDs, model
definitions) behave correctly — without requiring a running Qdrant
server or downloading embedding models.

Run with::

    cd tools/indexer
    pip install -e ".[dev]"
    pytest tests/
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import List

import pytest

# ---------------------------------------------------------------------------
# Import smoke tests — verify the package structure is intact
# ---------------------------------------------------------------------------


class TestImports:
    """Every public module should import without error."""

    def test_import_config(self):
        from cerberus_indexer import config

        assert hasattr(config, "QDRANT_URL")
        assert hasattr(config, "COLLECTION_NAME")
        assert hasattr(config, "DENSE_VECTOR_NAME")
        assert hasattr(config, "SPARSE_VECTOR_NAME")

    def test_import_models(self):
        from cerberus_indexer import models

        assert hasattr(models, "CodeChunk")
        assert hasattr(models, "Evidence")
        assert hasattr(models, "PatternEntry")
        assert hasattr(models, "PatternSpec")
        assert hasattr(models, "PATTERNS")

    def test_import_chunking(self):
        from cerberus_indexer import chunking

        assert callable(chunking.blake2s_hex)
        assert callable(chunking.deterministic_id)
        assert callable(chunking.chunk_words)
        assert callable(chunking.chunk_rust)
        assert callable(chunking.should_index_code)

    def test_import_patterns(self):
        from cerberus_indexer import patterns

        assert callable(patterns.mine_patterns)
        assert callable(patterns.find_files)

    def test_import_embeddings(self):
        from cerberus_indexer import embeddings

        assert hasattr(embeddings, "EmbeddingManager")
        assert hasattr(embeddings, "HybridEmbedding")
        assert hasattr(embeddings, "DenseEmbedding")
        assert hasattr(embeddings, "SparseEmbeddingResult")

    def test_import_qdrant_ops(self):
        from cerberus_indexer import qdrant_ops

        assert callable(qdrant_ops.ensure_collection)
        assert callable(qdrant_ops.ensure_payload_indexes)
        assert callable(qdrant_ops.build_code_points)
        assert callable(qdrant_ops.build_pattern_points)
        assert callable(qdrant_ops.build_store_point)

    def test_import_search(self):
        from cerberus_indexer import search

        assert callable(search.hybrid_search)
        assert callable(search.dense_search)
        assert callable(search.sparse_search)
        assert callable(search.format_results)

    def test_import_server(self):
        from cerberus_indexer import server

        assert hasattr(server, "mcp")
        assert callable(server.main)

    def test_import_cli(self):
        from cerberus_indexer import cli

        assert callable(cli.main)

    def test_package_version(self):
        import cerberus_indexer

        assert cerberus_indexer.__version__ == "0.3.0"


# ---------------------------------------------------------------------------
# blake2s_hex
# ---------------------------------------------------------------------------


class TestBlake2sHex:
    def test_deterministic(self):
        from cerberus_indexer.chunking import blake2s_hex

        result_a = blake2s_hex(b"hello world")
        result_b = blake2s_hex(b"hello world")
        assert result_a == result_b

    def test_different_inputs(self):
        from cerberus_indexer.chunking import blake2s_hex

        assert blake2s_hex(b"alpha") != blake2s_hex(b"beta")

    def test_hex_length(self):
        from crucible_indexer.chunking import blake2s_hex

        # BLAKE2s produces a 32-byte digest → 64 hex chars.
        result = blake2s_hex(b"test")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_empty_input(self):
        from crucible_indexer.chunking import blake2s_hex

        # Should not raise; empty bytes is valid.
        result = blake2s_hex(b"")
        assert isinstance(result, str)
        assert len(result) == 64


# ---------------------------------------------------------------------------
# deterministic_id
# ---------------------------------------------------------------------------


class TestDeterministicId:
    def test_returns_valid_uuid(self):
        from cerberus_indexer.chunking import deterministic_id

        result = deterministic_id("ns", "key")
        # Should be parseable as a UUID.
        parsed = uuid.UUID(result)
        assert str(parsed) == result

    def test_stable(self):
        from cerberus_indexer.chunking import deterministic_id

        a = deterministic_id("code", "foo.rs::0")
        b = deterministic_id("code", "foo.rs::0")
        assert a == b

    def test_different_namespaces(self):
        from cerberus_indexer.chunking import deterministic_id

        a = deterministic_id("code", "foo.rs::0")
        b = deterministic_id("pattern", "foo.rs::0")
        assert a != b

    def test_different_keys(self):
        from cerberus_indexer.chunking import deterministic_id

        a = deterministic_id("code", "foo.rs::0")
        b = deterministic_id("code", "foo.rs::1")
        assert a != b


# ---------------------------------------------------------------------------
# chunk_words
# ---------------------------------------------------------------------------


class TestChunkWords:
    def test_empty_text(self):
        from cerberus_indexer.chunking import chunk_words

        assert chunk_words("") == []

    def test_short_text_single_chunk(self):
        from crucible_indexer.chunking import chunk_words

        text = "one two three four"
        chunks = chunk_words(text, size=10, overlap=2)
        assert len(chunks) == 1
        assert chunks[0] == text

    def test_overlap_creates_more_chunks(self):
        from crucible_indexer.chunking import chunk_words

        text = " ".join(f"w{i}" for i in range(20))
        chunks_no_overlap = chunk_words(text, size=10, overlap=0)
        chunks_with_overlap = chunk_words(text, size=10, overlap=5)
        assert len(chunks_with_overlap) >= len(chunks_no_overlap)

    def test_each_chunk_has_at_most_size_words(self):
        from crucible_indexer.chunking import chunk_words

        text = " ".join(f"word{i}" for i in range(100))
        chunks = chunk_words(text, size=20, overlap=5)
        for chunk in chunks:
            assert len(chunk.split()) <= 20

    def test_whitespace_only(self):
        from crucible_indexer.chunking import chunk_words

        assert chunk_words("   \n\t  ") == []


# ---------------------------------------------------------------------------
# should_index_code
# ---------------------------------------------------------------------------


class TestShouldIndexCode:
    def test_rust_file_in_scope(self):
        from cerberus_indexer.chunking import should_index_code

        assert should_index_code(Path("cerberus/kernel/forge/src/lib.rs")) is True

    def test_excluded_directory(self):
        from crucible_indexer.chunking import should_index_code

        assert should_index_code(Path("target/release/foo.rs")) is False

    def test_git_directory(self):
        from crucible_indexer.chunking import should_index_code

        assert should_index_code(Path(".git/config")) is False

    def test_wrong_extension(self):
        from crucible_indexer.chunking import should_index_code

        assert should_index_code(Path("crucible/kernel/forge/src/lib.o")) is False

    def test_root_level_toml(self):
        from crucible_indexer.chunking import should_index_code

        # Files at root with valid extension should be in scope.
        assert should_index_code(Path("Cargo.toml")) is True

    def test_out_of_scope_path(self):
        from crucible_indexer.chunking import should_index_code

        assert should_index_code(Path("some/random/place/file.rs")) is False

    def test_indexer_excluded_from_indexing(self):
        """The indexer must not index itself."""
        from cerberus_indexer.chunking import should_index_code

        assert should_index_code(Path("tools/indexer/src/cerberus_indexer/indexer.py")) is False
        assert should_index_code(Path("tools/indexer/pyproject.toml")) is False
        assert should_index_code(Path("tools/indexer/README.md")) is False
        assert should_index_code(Path("tools/indexer/tests/test_smoke.py")) is False

    def test_other_tools_still_indexed(self):
        """Non-indexer files under tools/ should still be in scope."""
        from crucible_indexer.chunking import should_index_code

        assert should_index_code(Path("tools/boot-test.sh")) is True
        assert should_index_code(Path("tools/setup-pal.sh")) is True


# ---------------------------------------------------------------------------
# in_scope
# ---------------------------------------------------------------------------


class TestInScope:
    def test_matching_scope(self):
        from crucible_indexer.chunking import in_scope

        assert in_scope(Path("crucible/kernel/forge/src/lib.rs"), ["crucible/kernel"])

    def test_no_matching_scope(self):
        from crucible_indexer.chunking import in_scope

        assert not in_scope(Path("docs/README.md"), ["crucible/kernel"])

    def test_empty_scopes(self):
        from crucible_indexer.chunking import in_scope

        assert not in_scope(Path("anything"), [])


# ---------------------------------------------------------------------------
# batched
# ---------------------------------------------------------------------------


class TestBatched:
    def test_exact_batches(self):
        from crucible_indexer.chunking import batched

        items = list(range(10))
        batches = list(batched(items, 5))
        assert len(batches) == 2
        assert batches[0] == [0, 1, 2, 3, 4]
        assert batches[1] == [5, 6, 7, 8, 9]

    def test_remainder_batch(self):
        from crucible_indexer.chunking import batched

        items = list(range(7))
        batches = list(batched(items, 3))
        assert len(batches) == 3
        assert batches[0] == [0, 1, 2]
        assert batches[1] == [3, 4, 5]
        assert batches[2] == [6]

    def test_empty_iterable(self):
        from crucible_indexer.chunking import batched

        assert list(batched([], 10)) == []

    def test_single_item(self):
        from crucible_indexer.chunking import batched

        assert list(batched([42], 5)) == [[42]]


# ---------------------------------------------------------------------------
# collect_code_chunks
# ---------------------------------------------------------------------------


class TestCollectCodeChunks:
    def test_short_file_skipped(self, tmp_path: Path):
        from crucible_indexer.chunking import collect_code_chunks

        f = tmp_path / "tiny.rs"
        f.write_text("fn x() {}")  # 9 chars < 20
        assert collect_code_chunks(f, "tiny.rs") == []

    def test_normal_file_produces_chunks(self, tmp_path: Path):
        from crucible_indexer.chunking import collect_code_chunks

        # 500 words should produce at least 2 chunks with default settings.
        f = tmp_path / "big.rs"
        text = " ".join(f"word{i}" for i in range(500))
        f.write_text(text)

        chunks = collect_code_chunks(f, "big.rs", chunk_size=100, overlap=10)
        assert len(chunks) >= 2

        for chunk in chunks:
            assert chunk.file == "big.rs"
            assert chunk.language == "rs"
            assert chunk.total_chunks == len(chunks)
            assert 0 <= chunk.chunk_index < len(chunks)
            assert len(chunk.hash) == 64  # BLAKE2s hex

    def test_chunk_indices_sequential(self, tmp_path: Path):
        from crucible_indexer.chunking import collect_code_chunks

        f = tmp_path / "seq.rs"
        f.write_text(" ".join(f"w{i}" for i in range(300)))

        chunks = collect_code_chunks(f, "seq.rs", chunk_size=50, overlap=5)
        indices = [c.chunk_index for c in chunks]
        assert indices == list(range(len(chunks)))


# ---------------------------------------------------------------------------
# PatternSpec / PATTERNS table
# ---------------------------------------------------------------------------


class TestPatternTable:
    def test_patterns_non_empty(self):
        from crucible_indexer.models import PATTERNS

        assert len(PATTERNS) > 0

    def test_all_patterns_have_required_fields(self):
        from crucible_indexer.models import PATTERNS

        for spec in PATTERNS:
            assert spec.name, f"Pattern missing name: {spec}"
            assert spec.code_regex, f"Pattern {spec.name} missing code_regex"
            assert spec.doc_regex, f"Pattern {spec.name} missing doc_regex"
            assert spec.reason, f"Pattern {spec.name} missing reason"
            assert isinstance(spec.tags, list), f"Pattern {spec.name} tags not a list"
            assert isinstance(spec.scopes, list), f"Pattern {spec.name} scopes not a list"
            assert len(spec.scopes) > 0, f"Pattern {spec.name} has no scopes"


# ---------------------------------------------------------------------------
# Config sanity
# ---------------------------------------------------------------------------


class TestConfig:
    def test_vector_name_format(self):
        from crucible_indexer.config import DENSE_VECTOR_NAME, SPARSE_VECTOR_NAME

        assert DENSE_VECTOR_NAME.startswith("fast-")
        assert SPARSE_VECTOR_NAME == "bm25"

    def test_default_collection(self):
        from crucible_indexer.config import COLLECTION_NAME

        assert COLLECTION_NAME == "crucible-dev"

    def test_chunk_params_positive(self):
        from crucible_indexer.config import CHUNK_OVERLAP, CHUNK_WORDS

        assert CHUNK_WORDS > 0
        assert CHUNK_OVERLAP >= 0
        assert CHUNK_OVERLAP < CHUNK_WORDS

    def test_hybrid_limits_positive(self):
        from crucible_indexer.config import HYBRID_DEFAULT_LIMIT, HYBRID_PREFETCH_LIMIT

        assert HYBRID_DEFAULT_LIMIT > 0
        assert HYBRID_PREFETCH_LIMIT > 0
        assert HYBRID_PREFETCH_LIMIT >= HYBRID_DEFAULT_LIMIT

    def test_embed_batch_size_positive(self):
        from crucible_indexer.config import EMBED_BATCH_SIZE

        assert isinstance(EMBED_BATCH_SIZE, int)
        assert EMBED_BATCH_SIZE > 0

    def test_pipeline_queue_depth_positive(self):
        from crucible_indexer.config import PIPELINE_QUEUE_DEPTH

        assert isinstance(PIPELINE_QUEUE_DEPTH, int)
        assert PIPELINE_QUEUE_DEPTH > 0

    def test_upsert_workers_positive(self):
        from crucible_indexer.config import UPSERT_WORKERS

        assert isinstance(UPSERT_WORKERS, int)
        assert UPSERT_WORKERS >= 1

    def test_onnx_providers_non_empty(self):
        from crucible_indexer.config import ONNX_PROVIDERS

        assert isinstance(ONNX_PROVIDERS, list)
        assert len(ONNX_PROVIDERS) >= 1
        # CPU must always be present as the final fallback.
        assert "CPUExecutionProvider" in ONNX_PROVIDERS

    def test_onnx_providers_cpu_is_last(self):
        from crucible_indexer.config import ONNX_PROVIDERS

        assert ONNX_PROVIDERS[-1] == "CPUExecutionProvider"

    def test_onnx_threads_default_is_none(self):
        # When ONNX_THREADS env is not set, default should be None
        # (let onnxruntime choose).  If the env IS set in the test
        # environment, just verify it parsed to an int.
        import os

        from crucible_indexer.config import ONNX_THREADS

        if os.getenv("ONNX_THREADS") is None:
            assert ONNX_THREADS is None
        else:
            assert isinstance(ONNX_THREADS, int)
            assert ONNX_THREADS > 0


# ---------------------------------------------------------------------------
# SparseEmbeddingResult.to_qdrant (unit test — no model needed)
# ---------------------------------------------------------------------------


class TestSparseEmbeddingResult:
    def test_to_qdrant_roundtrip(self):
        from crucible_indexer.embeddings import SparseEmbeddingResult

        ser = SparseEmbeddingResult(indices=[0, 5, 12], values=[1.0, 0.5, 0.3])
        qvec = ser.to_qdrant()
        assert qvec.indices == [0, 5, 12]
        assert qvec.values == [1.0, 0.5, 0.3]


# ---------------------------------------------------------------------------
# ONNX provider detection (unit tests — no GPU required)
# ---------------------------------------------------------------------------


class TestOnnxProviderDetection:
    """Verify the provider auto-detection helpers without requiring a GPU."""

    def test_detect_returns_list(self):
        from crucible_indexer.config import _detect_onnx_providers

        result = _detect_onnx_providers()
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_detect_always_includes_cpu(self):
        from crucible_indexer.config import _detect_onnx_providers

        result = _detect_onnx_providers()
        assert "CPUExecutionProvider" in result

    def test_detect_cpu_is_last(self):
        from crucible_indexer.config import _detect_onnx_providers

        result = _detect_onnx_providers()
        assert result[-1] == "CPUExecutionProvider"

    def test_parse_env_single(self):
        from crucible_indexer.config import _parse_onnx_providers_env

        result = _parse_onnx_providers_env("CPUExecutionProvider")
        assert result == ["CPUExecutionProvider"]

    def test_parse_env_multiple(self):
        from crucible_indexer.config import _parse_onnx_providers_env

        result = _parse_onnx_providers_env("CUDAExecutionProvider,CPUExecutionProvider")
        assert result == ["CUDAExecutionProvider", "CPUExecutionProvider"]

    def test_parse_env_strips_whitespace(self):
        from crucible_indexer.config import _parse_onnx_providers_env

        result = _parse_onnx_providers_env(" CUDAExecutionProvider , CPUExecutionProvider ")
        assert result == ["CUDAExecutionProvider", "CPUExecutionProvider"]

    def test_parse_env_ignores_empty_segments(self):
        from crucible_indexer.config import _parse_onnx_providers_env

        result = _parse_onnx_providers_env("CUDAExecutionProvider,,CPUExecutionProvider,")
        assert result == ["CUDAExecutionProvider", "CPUExecutionProvider"]


# ---------------------------------------------------------------------------
# EmbeddingManager provider resolution (unit tests — no model download)
# ---------------------------------------------------------------------------


class TestEmbeddingManagerProviders:
    """Verify provider wiring without loading models."""

    def test_resolve_providers_default(self):
        from crucible_indexer.config import ONNX_PROVIDERS
        from crucible_indexer.embeddings import _resolve_providers

        result = _resolve_providers(None)
        assert result == list(ONNX_PROVIDERS)

    def test_resolve_providers_explicit(self):
        from crucible_indexer.embeddings import _resolve_providers

        result = _resolve_providers(["CPUExecutionProvider"])
        assert result == ["CPUExecutionProvider"]

    def test_resolve_providers_explicit_tuple(self):
        from crucible_indexer.embeddings import _resolve_providers

        result = _resolve_providers(("CUDAExecutionProvider", "CPUExecutionProvider"))
        assert result == ["CUDAExecutionProvider", "CPUExecutionProvider"]

    def test_manager_stores_providers(self):
        """EmbeddingManager should store provider list without loading models."""
        from crucible_indexer.embeddings import EmbeddingManager

        mgr = EmbeddingManager(providers=["CPUExecutionProvider"])
        assert mgr._providers == ["CPUExecutionProvider"]
        # Models should NOT be loaded yet (lazy init).
        assert mgr._dense_backend is None
        assert mgr._sparse is None

    def test_manager_default_providers_match_config(self):
        from crucible_indexer.config import ONNX_PROVIDERS
        from crucible_indexer.embeddings import EmbeddingManager

        mgr = EmbeddingManager()
        assert mgr._providers == list(ONNX_PROVIDERS)


# ---------------------------------------------------------------------------
# Pipeline data structures (unit tests — no Qdrant or models needed)
# ---------------------------------------------------------------------------


class TestPipelineStats:
    """Verify _PipelineStats counters and thread safety."""

    def test_default_values(self):
        from crucible_indexer.indexer import _PipelineStats

        stats = _PipelineStats()
        assert stats.total_chunks == 0
        assert stats.skipped_files == 0
        assert stats.upserted_points == 0
        assert stats.producer_errors == 0
        assert stats.embedder_errors == 0
        assert stats.upserter_errors == 0

    def test_lock_is_present(self):
        import threading

        from crucible_indexer.indexer import _PipelineStats

        stats = _PipelineStats()
        # threading.Lock is a factory function, not a type — check via
        # the internal _thread.lock type instead.
        assert type(stats.lock) is type(threading.Lock())

    def test_concurrent_increment(self):
        """Stats should survive concurrent increments from multiple threads."""
        import threading

        from crucible_indexer.indexer import _PipelineStats

        stats = _PipelineStats()
        barrier = threading.Barrier(4)

        def increment():
            barrier.wait()
            for _ in range(1000):
                with stats.lock:
                    stats.total_chunks += 1

        threads = [threading.Thread(target=increment) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert stats.total_chunks == 4000


class TestEmbedBatch:
    def test_construction(self):
        from crucible_indexer.indexer import _EmbedBatch
        from crucible_indexer.models import CodeChunk

        chunk = CodeChunk(
            file="test.rs",
            chunk_index=0,
            total_chunks=1,
            language="rs",
            hash="abc123",
            text="fn main() {}",
        )
        batch = _EmbedBatch(chunks=[chunk], file_hashes={"test.rs": "abc123"})
        assert len(batch.chunks) == 1
        assert batch.file_hashes["test.rs"] == "abc123"

    def test_empty_batch(self):
        from crucible_indexer.indexer import _EmbedBatch

        batch = _EmbedBatch(chunks=[])
        assert len(batch.chunks) == 0
        assert batch.file_hashes == {}


# ---------------------------------------------------------------------------
# search.format_result / format_results (unit tests — no Qdrant needed)
# ---------------------------------------------------------------------------


class TestFormatResults:
    def _make_scored_point(self, payload: dict, score: float = 0.95):
        """Build a minimal ScoredPoint-like object for formatting tests."""
        from qdrant_client.http.models import ScoredPoint

        return ScoredPoint(
            id="00000000-0000-0000-0000-000000000001",
            version=1,
            score=score,
            payload=payload,
        )

    def test_format_empty(self):
        from crucible_indexer.search import format_results

        assert "no results" in format_results([])

    def test_format_code_chunk(self):
        from crucible_indexer.search import format_result

        pt = self._make_scored_point(
            {
                "type": "code_chunk",
                "document": 'fn main() { println!("hello"); }',
                "metadata": {
                    "file": "src/main.rs",
                    "chunk_index": 0,
                    "total_chunks": 1,
                    "language": "rs",
                },
            }
        )
        text = format_result(pt, rank=1)
        assert "src/main.rs" in text
        assert "0.9500" in text
        assert "chunk 0/1" in text

    def test_format_pattern(self):
        from crucible_indexer.search import format_result

        pt = self._make_scored_point(
            {
                "type": "pattern",
                "pattern_name": "Determinism via BTreeMap",
                "reason": "Deterministic iteration for auditability.",
                "tags": ["determinism", "collections"],
                "evidence": [{"file_path": "a.rs", "line_start": 1}],
            }
        )
        text = format_result(pt, rank=2)
        assert "PATTERN" in text
        assert "BTreeMap" in text
        assert "determinism" in text

    def test_format_mcp_stored(self):
        from crucible_indexer.search import format_result

        pt = self._make_scored_point(
            {
                "type": "mcp_stored",
                "document": "Architecture decision: use RRF fusion for hybrid search.",
            }
        )
        text = format_result(pt, rank=1)
        assert "STORED" in text
        assert "RRF" in text

    def test_format_unknown_type(self):
        from crucible_indexer.search import format_result

        pt = self._make_scored_point({"type": "alien"})
        text = format_result(pt, rank=1)
        assert "alien" in text

    def test_format_results_multiple(self):
        from crucible_indexer.search import format_results

        pts = [
            self._make_scored_point(
                {"type": "code_chunk", "document": "chunk1", "metadata": {"file": "a.rs"}},
                score=0.9,
            ),
            self._make_scored_point(
                {"type": "code_chunk", "document": "chunk2", "metadata": {"file": "b.rs"}},
                score=0.8,
            ),
        ]
        text = format_results(pts)
        assert "a.rs" in text
        assert "b.rs" in text
        # Both ranks should appear.
        assert "1." in text
        assert "2." in text


# ---------------------------------------------------------------------------
# v0.3.0: CodeChunk new fields
# ---------------------------------------------------------------------------


class TestCodeChunkV3Fields:
    def test_default_fields(self):
        from crucible_indexer.models import CodeChunk

        chunk = CodeChunk(
            file="test.rs",
            chunk_index=0,
            total_chunks=1,
            language="rs",
            hash="abc",
            text="fn foo() {}",
        )
        assert chunk.line_start == 0
        assert chunk.line_end == 0
        assert chunk.symbols == []
        assert chunk.kind == "mixed"
        assert chunk.crate_name == ""
        assert chunk.subsystem == ""
        assert chunk.module_path == ""
        assert chunk.is_test is False
        assert chunk.is_unsafe is False
        assert chunk.calls == []
        assert chunk.doc_comment == ""

    def test_explicit_fields(self):
        from crucible_indexer.models import CodeChunk

        chunk = CodeChunk(
            file="crucible/kernel/forge-boot/src/main.rs",
            chunk_index=0,
            total_chunks=5,
            language="rs",
            hash="abc123",
            text="pub fn entry_point() {}",
            line_start=10,
            line_end=20,
            symbols=["entry_point"],
            kind="function",
            crate_name="forge-boot",
            subsystem="kernel",
            module_path="forge_boot::main",
            is_test=False,
            is_unsafe=False,
            calls=["init_gdt", "setup_idt"],
            doc_comment="/// Entry point for the boot stage.",
        )
        assert chunk.symbols == ["entry_point"]
        assert chunk.kind == "function"
        assert chunk.subsystem == "kernel"
        assert chunk.crate_name == "forge-boot"


# ---------------------------------------------------------------------------
# v0.3.0: Rust-aware chunking helpers
# ---------------------------------------------------------------------------


class TestChunkRust:
    def test_splits_on_fn_boundary(self):
        from crucible_indexer.chunking import chunk_rust

        # Small fns may be merged (intended behavior for grouping small items).
        # Use max_words=3 to force splitting at fn boundaries.
        src = """\
fn foo() {
    let x = 1;
}

fn bar() {
    let y = 2;
}
"""
        chunks = chunk_rust(src, "test.rs", max_words=3)
        # With max_words=3, each fn body exceeds limit → split.
        assert len(chunks) >= 2
        texts = [c[0] for c in chunks]
        assert any("foo" in t for t in texts)
        assert any("bar" in t for t in texts)

    def test_metadata_symbols_extracted(self):
        from crucible_indexer.chunking import chunk_rust

        src = """\
pub fn my_func(x: u32) -> u32 {
    x + 1
}
"""
        chunks = chunk_rust(src, "crucible/kernel/forge-boot/src/lib.rs")
        assert chunks
        _, _, _, meta = chunks[0]
        assert "my_func" in meta["symbols"]
        assert meta["kind"] == "function"

    def test_is_test_detected(self):
        from crucible_indexer.chunking import chunk_rust

        src = """\
#[test]
fn test_something() {
    assert_eq!(1, 1);
}
"""
        chunks = chunk_rust(src, "tests/test_boot.rs")
        assert chunks
        _, _, _, meta = chunks[0]
        assert meta["is_test"] is True

    def test_is_unsafe_detected(self):
        from crucible_indexer.chunking import chunk_rust

        src = """\
pub unsafe fn dangerous() {
    core::ptr::null::<u8>();
}
"""
        chunks = chunk_rust(src, "crucible/kernel/forge/src/lib.rs")
        assert chunks
        _, _, _, meta = chunks[0]
        assert meta["is_unsafe"] is True

    def test_fallback_for_empty(self):
        from crucible_indexer.chunking import chunk_rust

        chunks = chunk_rust("", "test.rs")
        assert chunks == []

    def test_line_numbers(self):
        from crucible_indexer.chunking import chunk_rust

        src = "fn a() {}\n\nfn b() {}\n"
        chunks = chunk_rust(src, "test.rs")
        assert chunks
        for _, line_start, line_end, _ in chunks:
            assert isinstance(line_start, int)
            assert isinstance(line_end, int)
            assert line_end >= line_start


class TestDeriveHelpers:
    def test_derive_subsystem_kernel(self):
        from crucible_indexer.chunking import _derive_subsystem

        assert _derive_subsystem("crucible/kernel/forge-boot/src/main.rs") == "kernel"

    def test_derive_subsystem_runtime(self):
        from crucible_indexer.chunking import _derive_subsystem

        assert _derive_subsystem("crucible/runtime/temper/src/lib.rs") == "runtime"

    def test_derive_subsystem_tools(self):
        from crucible_indexer.chunking import _derive_subsystem

        assert _derive_subsystem("tools/setup-pal.sh") == "tools"

    def test_derive_subsystem_unknown(self):
        from crucible_indexer.chunking import _derive_subsystem

        assert _derive_subsystem("random/path/file.rs") == ""

    def test_derive_crate_name(self):
        from crucible_indexer.chunking import _derive_crate_name

        assert _derive_crate_name("crucible/kernel/forge-boot/src/main.rs") == "forge-boot"
        assert _derive_crate_name("crucible/runtime/temper/src/lib.rs") == "temper"

    def test_derive_module_path(self):
        from crucible_indexer.chunking import _derive_module_path

        assert (
            _derive_module_path("crucible/kernel/forge-boot/src/ledgerfs_boot.rs")
            == "forge_boot::ledgerfs_boot"
        )

    def test_derive_module_path_lib(self):
        from crucible_indexer.chunking import _derive_module_path

        # lib.rs is the crate root — returns crate name only.
        assert _derive_module_path("crucible/kernel/forge-boot/src/lib.rs") == "forge_boot"

    def test_derive_module_path_non_rust(self):
        from crucible_indexer.chunking import _derive_module_path

        assert _derive_module_path("README.md") == ""


# ---------------------------------------------------------------------------
# v0.3.0: PATTERNS table size
# ---------------------------------------------------------------------------


class TestNewPatterns:
    def test_patterns_count_increased(self):
        from crucible_indexer.models import PATTERNS

        # v0.3.0 adds 11 new patterns to the original 10.
        assert len(PATTERNS) >= 20

    def test_new_pattern_names_present(self):
        from crucible_indexer.models import PATTERNS

        names = {p.name for p in PATTERNS}
        assert "Boot phase breadcrumbs" in names
        assert "LedgerFS on-disk layout" in names
        assert "Kernel syscall interface" in names
        assert "ATA PIO disk I/O" in names
        assert "Cryptographic verification (ML-DSA / SLH-DSA / BLAKE3)" in names


# ---------------------------------------------------------------------------
# v0.3.0: _build_filter new params
# ---------------------------------------------------------------------------


class TestBuildFilterV3:
    def test_subsystem_filter(self):
        from crucible_indexer.search import _build_filter

        flt = _build_filter(subsystem="kernel")
        assert flt is not None
        keys = [c.key for c in flt.must]
        assert "metadata.subsystem" in keys

    def test_crate_filter(self):
        from crucible_indexer.search import _build_filter

        flt = _build_filter(crate="forge-boot")
        assert flt is not None
        keys = [c.key for c in flt.must]
        assert "metadata.crate" in keys

    def test_kind_filter(self):
        from crucible_indexer.search import _build_filter

        flt = _build_filter(kind="function")
        assert flt is not None
        keys = [c.key for c in flt.must]
        assert "metadata.kind" in keys

    def test_symbols_filter(self):
        from crucible_indexer.search import _build_filter

        flt = _build_filter(symbols=["entry_point", "init"])
        assert flt is not None
        keys = [c.key for c in flt.must]
        assert keys.count("metadata.declared") == 2

    def test_exclude_tests_filter(self):
        from crucible_indexer.search import _build_filter

        flt = _build_filter(exclude_tests=True)
        assert flt is not None
        keys = [c.key for c in flt.must]
        assert "metadata.is_test" in keys

    def test_no_filters_returns_none(self):
        from crucible_indexer.search import _build_filter

        assert _build_filter() is None

    def test_combined_filters(self):
        from crucible_indexer.search import _build_filter

        flt = _build_filter(subsystem="kernel", crate="forge-boot", kind="function")
        assert flt is not None
        keys = [c.key for c in flt.must]
        assert "metadata.subsystem" in keys
        assert "metadata.crate" in keys
        assert "metadata.kind" in keys


# ---------------------------------------------------------------------------
# v0.3.0: Server imports the new tool descriptions
# ---------------------------------------------------------------------------


class TestServerV3:
    def test_crucible_search_registered(self):
        from crucible_indexer import server

        # FastMCP registers tools; verify the new functions are present.
        assert callable(server.crucible_search)
        assert callable(server.trace)

    def test_config_has_new_descriptions(self):
        from crucible_indexer.config import TOOL_SEARCH_DESCRIPTION, TOOL_TRACE_DESCRIPTION

        assert "subsystem" in TOOL_SEARCH_DESCRIPTION and "kind" in TOOL_SEARCH_DESCRIPTION
        assert "symbol" in TOOL_TRACE_DESCRIPTION


# ---------------------------------------------------------------------------
# v0.4.0: Improved symbol/call extraction (cleaner metadata)
# ---------------------------------------------------------------------------


class TestChunkRustMetadataFixes:
    """Verify the improved symbol and call extraction logic."""

    def test_mut_not_in_symbols(self):
        """'mut' must not appear in symbols (from 'static mut SOMETHING')."""
        from crucible_indexer.chunking import chunk_rust

        src = """\
static mut LOGGER: Option<SerialLogger> = None;

pub fn init() {}
"""
        chunks = chunk_rust(src, "test.rs")
        assert chunks
        all_symbols = [s for _, _, _, meta in chunks for s in meta["symbols"]]
        assert "mut" not in all_symbols

    def test_const_not_in_symbols_but_in_declared(self):
        """Constants are in 'declared' but not in 'symbols' (traceable only)."""
        from crucible_indexer.chunking import chunk_rust

        src = """\
const DIAG_STACK_SIZE: usize = 4096;

pub fn do_work() {}
"""
        chunks = chunk_rust(src, "test.rs")
        assert chunks
        all_symbols = [s for _, _, _, meta in chunks for s in meta["symbols"]]
        all_declared = [s for _, _, _, meta in chunks for s in meta["declared"]]
        assert "DIAG_STACK_SIZE" not in all_symbols
        assert "DIAG_STACK_SIZE" in all_declared

    def test_fn_in_both_symbols_and_declared(self):
        """Functions appear in both 'symbols' and 'declared'."""
        from crucible_indexer.chunking import chunk_rust

        src = "pub fn my_func() {}\n"
        chunks = chunk_rust(src, "test.rs")
        assert chunks
        _, _, _, meta = chunks[0]
        assert "my_func" in meta["symbols"]
        assert "my_func" in meta["declared"]

    def test_cfg_not_in_calls(self):
        """'cfg' must not appear in calls (it's a Rust attribute, not a call)."""
        from crucible_indexer.chunking import chunk_rust

        src = """\
#[cfg(target_os = "crucible")]
pub fn platform_init() {
    inline_init();
}
"""
        chunks = chunk_rust(src, "test.rs")
        assert chunks
        all_calls = [c for _, _, _, meta in chunks for c in meta["calls"]]
        assert "cfg" not in all_calls
        assert "inline" not in all_calls
        assert "target_os" not in all_calls

    def test_derive_not_in_calls(self):
        """'derive' must not appear in calls (it's an attribute macro)."""
        from crucible_indexer.chunking import chunk_rust

        src = """\
#[derive(Debug, Clone)]
pub struct MyStruct {
    value: u32,
}
"""
        chunks = chunk_rust(src, "test.rs")
        assert chunks
        all_calls = [c for _, _, _, meta in chunks for c in meta["calls"]]
        assert "derive" not in all_calls

    def test_pascal_case_method_calls_preserved(self):
        """Method calls like 'new' from BootInfo::new() must be captured."""
        from crucible_indexer.chunking import chunk_rust

        src = """\
pub fn create() {
    let info = BootInfo::new(addr);
    let logger = SerialLogger::init(port);
}
"""
        chunks = chunk_rust(src, "test.rs")
        assert chunks
        all_calls = [c for _, _, _, meta in chunks for c in meta["calls"]]
        # 'new' and 'init' should be captured (they are the actual method calls)
        assert "new" in all_calls
        assert "init" in all_calls

    def test_allow_not_in_calls(self):
        """'allow' must not appear in calls (it's a compiler attribute)."""
        from crucible_indexer.chunking import chunk_rust

        src = """\
#[allow(dead_code)]
pub fn unused_fn() {}
"""
        chunks = chunk_rust(src, "test.rs")
        assert chunks
        all_calls = [c for _, _, _, meta in chunks for c in meta["calls"]]
        assert "allow" not in all_calls

    def test_declared_field_in_codechunk(self):
        """CodeChunk.declared field should be populated by collect_code_chunks."""
        import tempfile
        from pathlib import Path

        from crucible_indexer.chunking import collect_code_chunks

        src = """\
const MAX_SIZE: usize = 1024;
static mut BUFFER: [u8; 1024] = [0; 1024];
pub fn process() {}
pub struct Worker {}
"""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(src)
            tmp = Path(f.name)

        chunks = collect_code_chunks(tmp, "test.rs")
        tmp.unlink()

        assert chunks
        all_declared = [d for chunk in chunks for d in chunk.declared]
        all_symbols = [s for chunk in chunks for s in chunk.symbols]

        # Constants and statics in declared but not symbols
        assert "MAX_SIZE" in all_declared
        assert "MAX_SIZE" not in all_symbols
        # Functions and structs in both
        assert "process" in all_declared
        assert "process" in all_symbols
        assert "Worker" in all_declared
        assert "Worker" in all_symbols

    def test_build_filter_uses_declared_for_symbols(self):
        """_build_filter should filter on metadata.declared (not metadata.symbols)."""
        from crucible_indexer.search import _build_filter

        flt = _build_filter(symbols=["my_const", "my_fn"])
        assert flt is not None
        keys = [c.key for c in flt.must]
        # Should use declared field (superset of symbols)
        assert all(k == "metadata.declared" for k in keys)
        assert "metadata.symbols" not in keys


# ---------------------------------------------------------------------------
# qdrant-reindex tool and CRUCIBLE_REPO_ROOT config
# ---------------------------------------------------------------------------


class TestReindexTool:
    """Verify that qdrant_reindex is importable and the server exposes it."""

    def test_import_qdrant_reindex(self):
        from crucible_indexer.server import qdrant_reindex

        assert callable(qdrant_reindex)

    def test_reindex_tool_registered(self):
        """The mcp app should have 'qdrant-reindex' in its tool list."""
        from crucible_indexer.server import mcp

        tool_names = [t.name for t in mcp._tool_manager.list_tools()]
        assert "qdrant-reindex" in tool_names

    def test_reindex_description_non_empty(self):
        from crucible_indexer.config import TOOL_REINDEX_DESCRIPTION

        assert isinstance(TOOL_REINDEX_DESCRIPTION, str)
        assert len(TOOL_REINDEX_DESCRIPTION) > 20


class TestCrucibleRepoRoot:
    """Verify CRUCIBLE_REPO_ROOT resolution from config."""

    def test_crucible_repo_root_is_path(self):
        from pathlib import Path

        from crucible_indexer.config import CRUCIBLE_REPO_ROOT

        assert isinstance(CRUCIBLE_REPO_ROOT, Path)

    def test_crucible_repo_root_env_override(self, tmp_path, monkeypatch):
        import importlib

        import crucible_indexer.config as cfg

        monkeypatch.setenv("CRUCIBLE_REPO_ROOT", str(tmp_path))
        importlib.reload(cfg)
        assert cfg.CRUCIBLE_REPO_ROOT == tmp_path
        # Restore original module state after test.
        monkeypatch.delenv("CRUCIBLE_REPO_ROOT", raising=False)
        importlib.reload(cfg)
