# cerberus-indexer

**Cerberus repository indexer and hybrid MCP server.**

Dense (MiniLM) + sparse (BM25) vector embeddings for every code chunk and
architecture pattern in the repository, with Reciprocal Rank Fusion (RRF)
at query time.

**v0.2.0** — 3-stage pipeline parallelism, GPU acceleration (default with
CPU fallback), cross-file batch accumulation, and concurrent Qdrant upserts.

---

## Why this exists

The upstream [`mcp-server-qdrant`](https://github.com/qdrant/mcp-server-qdrant)
is **dense-only** — it embeds queries with a single MiniLM model and runs
cosine similarity.  That works well for broad conceptual searches but
misses exact symbol names, capability IDs, function signatures, and other
keyword-heavy queries that matter in a systems codebase.

This project replaces it with a **hybrid** approach:

| Leg | Model | Good at |
|-----|-------|---------|
| Dense | `sentence-transformers/all-MiniLM-L6-v2` | Semantic / conceptual queries |
| Sparse | `Qdrant/bm25` (fastembed) | Exact keywords, symbol names, IDs |
| **Fused** | Reciprocal Rank Fusion (RRF) | **Both** |

Every point in the collection carries **two named vectors**.  At query time,
two prefetch legs retrieve candidates independently, and Qdrant's server-side
RRF merges them into a single ranked list.

---

## Project layout

```text
tools/indexer/
├── pyproject.toml              # Package definition, deps, entry points
├── README.md                   # ← you are here
├── mcp-server-cerberus         # Shell launcher for Zed / Claude Desktop
├── src/
│   └── cerberus_indexer/
│       ├── __init__.py         # Package marker + version
│       ├── config.py           # All tunables (env vars with defaults)
│       ├── models.py           # Dataclasses: CodeChunk, Evidence, PatternEntry, PatternSpec
│       ├── chunking.py         # Text chunking, BLAKE2s hashing, deterministic IDs
│       ├── patterns.py         # Pattern mining (regex-based evidence collection)
│       ├── embeddings.py       # Unified dense + sparse embedding wrapper
│       ├── qdrant_ops.py       # Collection management, point building, deletion
│       ├── search.py           # Hybrid / dense-only / sparse-only search + formatting
│       ├── indexer.py          # Main indexing pipeline (code chunks + patterns)
│       ├── server.py           # Hybrid MCP server (drop-in replacement for mcp-server-qdrant)
│       └── cli.py              # CLI entry point for indexing + interactive search
└── tests/
    └── test_smoke.py           # Import + unit tests (no Qdrant / models required)
```

### Entry points

| Command | What it does |
|---------|-------------|
| `cerberus-index` | Index the repository and/or run interactive search |
| `cerberus-mcp-server` | Launch the hybrid MCP server (stdio transport) |

---

## Prerequisites

1. **Python ≥ 3.11**

2. **Qdrant server** (v1.14+ for sparse vectors and RRF fusion):

   ```bash
   docker run -p 6333:6333 -p 6334:6334 qdrant/qdrant:latest
   ```

3. **Install the package** (editable mode recommended during development):

   ```bash
   cd tools/indexer
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

   This installs `fastembed`, `qdrant-client`, `mcp[cli]`, `pytest`, and `ruff`.

4. **(Recommended) GPU acceleration** — install a GPU-enabled ONNX Runtime
   for 5–20× faster embedding:

   ```bash
   # NVIDIA CUDA (most common)
   pip install -e ".[cuda]"

   # AMD ROCm
   pip install -e ".[rocm]"

   # Windows DirectML
   pip install -e ".[directml]"
   ```

   If no GPU runtime is installed, the indexer automatically falls back to
   CPU.  See [GPU Acceleration](#gpu-acceleration) below.

---

## Indexing the codebase

Run from the **Cerberus repository root**:

```bash
# First time — creates the collection with both dense + sparse vectors
cerberus-index --recreate

# Subsequent runs — only re-indexes changed files (BLAKE2s hash check)
cerberus-index

# Skip pattern mining (faster, code chunks only)
cerberus-index --no-patterns

# Skip code chunks (patterns only)
cerberus-index --no-code
```

Incremental state is saved to `.qdrant-index-state.json` in the repo root.
Delete it to force a full re-index.

### Performance tuning flags

```bash
# Larger embedding batches (better GPU utilisation for big repos)
cerberus-index --embed-batch-size 512

# Multiple upsert workers (for remote / high-latency Qdrant)
cerberus-index --upsert-workers 3

# Combine
cerberus-index --recreate --embed-batch-size 512 --upsert-workers 2
```

### What gets indexed

- **Code chunks**: Every in-scope `.rs`, `.toml`, `.md`, `.sh`, `.json`,
  `.yml`, `.yaml`, `.txt` file is split into overlapping word-level chunks
  (400 words, 50-word overlap).  Each chunk becomes a Qdrant point with
  both dense and sparse vectors.

- **Architecture patterns**: Regex-based pattern mining detects recurring
  idioms (BTreeMap determinism, capability gates, no\_std imports, domain
  separation, etc.) with code evidence and doc snippets.

---

## Interactive search (CLI)

Instead of indexing, you can search the collection from the terminal:

### Hybrid search (default — recommended)

```bash
cerberus-index --query "IPC dispatch loop pattern cerberus"
cerberus-index --query "capability ID allocation"
```

### Dense-only (semantic similarity)

```bash
cerberus-index --query "how does the kernel handle page faults" --dense-only
```

### Sparse-only (BM25 keyword matching)

```bash
cerberus-index --query "FixedFdTable register CapabilityId" --sparse-only
```

### Filters

```bash
# Only code chunks
cerberus-index --query "BTreeMap" --type code_chunk

# Only patterns
cerberus-index --query "OnceLock" --type pattern

# File path substring
cerberus-index --query "write" --file "fs-cbl"

# More results
cerberus-index --query "IPC" --limit 20

# Combine everything
cerberus-index --query "capability table" --type code_chunk --file "kernel/forge" --limit 15
```

---

## MCP server (Zed / Claude Desktop / Cursor)

The hybrid MCP server is a **drop-in replacement** for `mcp-server-qdrant`.
It exposes `cerberus-search`, `trace`, and `qdrant-store` with hybrid
search under the hood.

### Zed configuration

In your Zed `settings.json`:

```jsonc
{
  "context_servers": {
    "cerberus-qdrant": {
      "command": {
        "path": "/absolute/path/to/Cerberus/tools/indexer/mcp-server-cerberus"
      }
    }
  }
}
```

Or, if you have the package installed and on PATH:

```jsonc
{
  "context_servers": {
    "cerberus-qdrant": {
      "command": {
        "path": "cerberus-mcp-server",
        "args": ["--transport", "stdio"]
      }
    }
  }
}
```

### Claude Desktop configuration

```jsonc
{
  "mcpServers": {
    "cerberus-qdrant": {
      "command": "/path/to/Cerberus/tools/indexer/mcp-server-cerberus",
      "env": {
        "QDRANT_URL": "http://localhost:6333",
        "COLLECTION_NAME": "cerberus-dev"
      }
    }
  }
}
```

### What the tools do

| Tool | Description |
|------|-------------|
| `cerberus-search` | **Hybrid dense+sparse → RRF fusion** with subsystem/crate/kind filters |
| `trace` | Call-chain traversal (callers / callees) for a given symbol |
| `qdrant-reindex` | **Incremental re-index** — detects changed files via BLAKE2s hashing, re-chunks/embeds only what changed, cleans up deleted files. Call after code changes. |
| `qdrant-store` | Agent notebook — persist insights, decisions, and session notes (NOT for code indexing). Stored notes appear in `cerberus-search` results. |

This means every point stored by the MCP server is immediately
discoverable by both semantic and keyword search.

---

## GPU Acceleration

The dense embedding model (MiniLM) runs on ONNX Runtime.  By default the
indexer **auto-detects GPU providers** at startup and falls back to CPU
if none are available.  Provider priority:

| Priority | Provider | Package required |
|----------|----------|-----------------|
| 1 | TensorRT | `onnxruntime-gpu` + TensorRT SDK |
| 2 | **CUDA** | `onnxruntime-gpu` |
| 3 | DirectML | `onnxruntime-directml` |
| 4 | ROCm | `onnxruntime-rocm` |
| 5 | **CPU** *(always available)* | `onnxruntime` (bundled by fastembed) |

### Quick start (NVIDIA)

```bash
# Replace the CPU-only onnxruntime with the GPU build
pip uninstall -y onnxruntime
pip install onnxruntime-gpu

# Or use the convenience extra
pip install -e ".[cuda]"
```

The indexer logs the active provider at startup:

```
INFO: Dense model ONNX providers: CUDAExecutionProvider (CPU fallback: yes)
INFO: 🚀 GPU acceleration ACTIVE (CUDAExecutionProvider)
```

If GPU initialisation fails (driver mismatch, OOM, etc.) the indexer
logs a warning and retries with CPU automatically — **indexing never
fails due to a GPU issue**.

### Force CPU-only

```bash
ONNX_PROVIDERS="CPUExecutionProvider" crucible-index
```

> **Note:** The sparse BM25 model is a statistical tokeniser, not a
> neural network.  It always runs on CPU regardless of GPU settings.

---

## Pipeline Architecture (v0.2.0)

The code-chunk indexing pipeline uses **3 concurrent stages** to overlap
CPU-bound embedding with file I/O and network I/O:

```text
┌──────────────────┐   embed_q   ┌──────────────────┐   upsert_q   ┌──────────────────┐
│  Stage A:        │ ──────────→ │  Stage B:         │ ───────────→ │  Stage C:        │
│  Producer        │             │  Embedder          │             │  Upserter         │
│  (bg thread)     │             │  (main thread)     │             │  (bg thread(s))   │
│                  │             │                    │             │                   │
│ • Walk repo      │             │ • Dense MiniLM     │             │ • HTTP upsert     │
│ • BLAKE2s hash   │             │   (GPU or CPU)     │             │ • Batch splitting │
│ • Skip unchanged │             │ • Sparse BM25      │             │ • State update    │
│ • Delete stale   │             │ • Build points     │             │                   │
│ • Chunk text     │             │                    │             │                   │
│ • Accumulate     │             │                    │             │                   │
│   coarse batches │             │                    │             │                   │
└──────────────────┘             └──────────────────┘             └──────────────────┘
```

### Key design decisions

1. **Cross-file batch accumulation** — Chunks from multiple files are
   accumulated into large batches (default 256 chunks) before embedding.
   This gives ONNX Runtime much better throughput on both GPU and CPU
   compared to per-file embedding.

2. **Embedding on the main thread** — The ONNX Runtime session is not
   thread-safe; all inference stays on the main thread.  Concurrency
   comes from overlapping I/O stages around it.

3. **State updates after upsert** — `file → hash` state is written only
   after the upserter successfully pushes points to Qdrant.  If upsert
   fails, the file will be re-indexed on the next run.

4. **Bounded queues** — Inter-stage queues have a configurable depth
   (`PIPELINE_QUEUE_DEPTH`, default 2) so memory stays bounded even for
   very large repositories.

### Expected speedup

| Scenario | Before (sequential) | After (pipeline) | Speedup |
|----------|-------------------|-----------------|---------|
| Full re-index, CPU | Baseline | ~2–3× | I/O overlaps embedding |
| Full re-index, CUDA GPU | Baseline | ~5–20× | GPU + overlap |
| Incremental (few files changed) | Baseline | ~1.5× | Less I/O to overlap |

---

## Environment variables

All configuration is via environment variables with sensible defaults:

| Variable | Default | Purpose |
|----------|---------|---------|
| `QDRANT_URL` | `http://localhost:6333` | Qdrant server address |
| `QDRANT_API_KEY` | *(none)* | API key (for Qdrant Cloud) |
| `COLLECTION_NAME` | `cerberus-dev` | Default collection name |
| `EMBEDDING_MODEL` | `sentence-transformers/all-MiniLM-L6-v2` | Dense embedding model |
| `SPARSE_MODEL` | `Qdrant/bm25` | Sparse embedding model |
| `ONNX_PROVIDERS` | *(auto-detect GPU → CPU)* | Comma-separated ONNX execution providers |
| `ONNX_THREADS` | *(onnxruntime default)* | Intra-op thread count for ONNX Runtime |
| `EMBED_BATCH_SIZE` | `256` | Chunks accumulated before embedding (larger = better GPU throughput) |
| `UPSERT_WORKERS` | `1` | Threads for Qdrant upsert I/O |
| `PIPELINE_QUEUE_DEPTH` | `2` | Max batches buffered between pipeline stages |
| `TOOL_STORE_DESCRIPTION` | *(see config.py)* | MCP tool description for `qdrant-store` |
| `TOOL_REINDEX_DESCRIPTION` | *(see config.py)* | MCP tool description for `qdrant-reindex` |
| `CERBERUS_REPO_ROOT` | *(auto from launcher)* | Absolute path to repo root (for `qdrant-reindex`) |

---

## Development

### Running tests

```bash
cd tools/indexer
pip install -e ".[dev]"
pytest tests/ -v
```

The smoke tests verify imports, pure-logic utilities, and formatting
without requiring a running Qdrant server or downloading embedding models.

### Linting

```bash
ruff check src/ tests/
ruff format src/ tests/
```

### Architecture

```text
┌─────────────────────────────────────────────┐
│  Zed / Claude Desktop / Cursor              │
│  (MCP host)                                 │
└──────────────┬──────────────────────────────┘
               │ stdio (MCP protocol)
               ▼
┌─────────────────────────────────────────────┐
│  server.py  (FastMCP)                       │
│                                             │
│  crucible-search ─→ hybrid prefetch + RRF + filters │
│  trace       ─→ call-chain traversal        │
│  qdrant-reindex ─→ incremental code index   │
│  qdrant-store ─→ agent notebook upsert      │
└──────────────┬──────────────────────────────┘
               │
       ┌───────┴───────┐
       ▼               ▼
┌──────────┐   ┌───────────────┐
│ fastembed │   │ qdrant-client │
│ (dense   │   │               │
│  GPU/CPU)│   │  ┌─────────┐  │
│ (sparse) │   │  │ Qdrant  │  │
└──────────┘   │  │ Server  │  │
               │  └─────────┘  │
               └───────────────┘
```

---

## Migration from v0.1.0

If upgrading from cerberus-indexer v0.1.0, no action is needed — the
pipeline, GPU, and batching changes are fully backward-compatible.  Your
existing Qdrant collection and state file work as-is.

To take advantage of GPU acceleration, install `onnxruntime-gpu`:

```bash
pip uninstall -y onnxruntime
pip install onnxruntime-gpu
```

The indexer auto-detects the GPU provider and logs it at startup.

---

## Migration from `mcp-qdrant-crucible`

If you were previously using the old `mcp-qdrant-crucible` script at the
repo root:

1. **Re-index** with the new tool to add sparse vectors to all points:

   ```bash
   crucible-index --recreate
   ```

2. **Update your Zed settings** to point to the new launcher:

   ```diff
   - "path": "/path/to/CrucibleOS/mcp-qdrant-crucible"
   + "path": "/path/to/CrucibleOS/tools/indexer/mcp-server-crucible"
   ```

3. The old `mcp-qdrant-crucible` and `index-crucible.py` at the repo root
   can be retired once you confirm the new server works.

---

## License

Same as Cerberus — see the repository root `LICENSE` file.