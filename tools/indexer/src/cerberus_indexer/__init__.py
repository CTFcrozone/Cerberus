"""
cerberus_indexer — Cerberus repository indexer and hybrid MCP server.

Provides:

- **Hybrid indexing**: Dense (MiniLM) + sparse (BM25) vector embeddings
  for every code chunk and architecture pattern in the repository.

- **Hybrid MCP server**: Drop-in replacement for ``mcp-server-qdrant``
  that uses Reciprocal Rank Fusion (RRF) to combine dense semantic
  search with sparse keyword matching — so both conceptual queries
  and exact symbol lookups return high-quality results.

- **CLI**: ``cerberus-index`` for indexing and interactive search,
  ``cerberus-mcp-server`` for launching the MCP server.
"""

__version__ = "0.3.0"

# Backwards-compatibility: expose the legacy package name `crucible_indexer`
# so code/tests that still reference `crucible_indexer` continue to work.
# This registers the current module under the old import name in sys.modules.
import sys as _sys

if "crucible_indexer" not in _sys.modules:
    _sys.modules["crucible_indexer"] = _sys.modules[__name__]
