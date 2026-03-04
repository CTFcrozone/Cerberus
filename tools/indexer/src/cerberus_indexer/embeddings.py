"""
Unified dense + sparse embedding wrapper.

Wraps either fastembed's ``TextEmbedding`` (ONNX) **or**
``sentence_transformers.SentenceTransformer`` (PyTorch) for dense
embeddings, plus fastembed's ``SparseTextEmbedding`` (BM25) for sparse
— behind a single :class:`EmbeddingManager` that both the indexer
pipeline and the MCP server can share.

Backend Selection
-----------------
Set ``EMBEDDING_BACKEND`` to choose the dense embedding engine:

``fastembed`` (default)
    Uses ONNX Runtime via fastembed.  Best when the model is in
    fastembed's curated list and you want lightweight CPU inference.

``sentence-transformers``
    Uses PyTorch via the ``sentence-transformers`` library.  Required
    for models that don't ship ONNX weights in fastembed (e.g.
    ModernBERT-based models like IBM Granite).  Supports Flash
    Attention 2, half-precision, and broader HuggingFace Hub models.

    Install the optional extra::

        pip install -e ".[st]"

GPU Acceleration
----------------
**fastembed backend**: GPU providers are auto-detected at import time
(see :mod:`cerberus_indexer.config`).  Priority order is
TensorRT > CUDA > DirectML > ROCm > CPU.  Override with
``ONNX_PROVIDERS``.

**sentence-transformers backend**: PyTorch device selection is
automatic (CUDA if available, else CPU).  Override with
``EMBEDDING_DEVICE`` env var (e.g. ``cpu``, ``cuda``, ``cuda:1``).

Thread-safety note
------------------
Neither fastembed nor sentence-transformers models are thread-safe.
The ``EmbeddingManager`` is designed to be used from a single thread
(or behind an asyncio executor boundary).  The indexer pipeline calls
:meth:`embed_passages` from the main thread only; the MCP server
dispatches embedding calls via
``asyncio.get_event_loop().run_in_executor(...)`` to avoid blocking
the event loop.
"""

from __future__ import annotations

import asyncio
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional, Sequence

from fastembed import SparseTextEmbedding
from qdrant_client.http import models as qmodels

if TYPE_CHECKING:
    from fastembed import TextEmbedding
    from sentence_transformers import SentenceTransformer

from cerberus_indexer.config import (
    DENSE_MODEL,
    DENSE_VECTOR_NAME,
    EMBEDDING_BACKEND,
    ONNX_PROVIDERS,
    ONNX_THREADS,
    SPARSE_MODEL,
    SPARSE_VECTOR_NAME,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lightweight result types
# ---------------------------------------------------------------------------


@dataclass
class DenseEmbedding:
    """A dense float vector ready for Qdrant upsert."""

    values: List[float]


@dataclass
class SparseEmbeddingResult:
    """A sparse vector (index/value pairs) ready for Qdrant upsert."""

    indices: List[int]
    values: List[float]

    def to_qdrant(self) -> qmodels.SparseVector:
        """Convert to a :class:`qdrant_client.http.models.SparseVector`."""
        return qmodels.SparseVector(indices=self.indices, values=self.values)


@dataclass
class HybridEmbedding:
    """A paired (dense, sparse) embedding for a single text."""

    dense: DenseEmbedding
    sparse: SparseEmbeddingResult


# ---------------------------------------------------------------------------
# Dense backend protocol
# ---------------------------------------------------------------------------


class DenseBackend(ABC):
    """
    Abstract interface for a dense embedding backend.

    Concrete implementations wrap either fastembed (ONNX) or
    sentence-transformers (PyTorch).
    """

    @abstractmethod
    def passage_embed(self, texts: List[str]) -> List[List[float]]:
        """Embed a batch of passages (document side)."""
        ...

    @abstractmethod
    def query_embed(self, text: str) -> List[float]:
        """Embed a single query."""
        ...

    @abstractmethod
    def get_dimension(self) -> int:
        """Return the embedding dimensionality."""
        ...

    @abstractmethod
    def get_active_provider(self) -> str:
        """Return a human-readable string describing the active device/provider."""
        ...


# ---------------------------------------------------------------------------
# fastembed backend (ONNX)
# ---------------------------------------------------------------------------


def _resolve_providers(
    explicit: Optional[Sequence[str]] = None,
) -> List[str]:
    """
    Return the ONNX execution provider list to use.

    Parameters
    ----------
    explicit:
        If supplied, use this list verbatim (caller override).
        Otherwise fall back to the auto-detected / env-configured
        :data:`crucible_indexer.config.ONNX_PROVIDERS`.

    Returns
    -------
    List[str]
        Provider names ready for fastembed / onnxruntime.
    """
    if explicit is not None:
        return list(explicit)
    return list(ONNX_PROVIDERS)


def _log_active_provider(providers: List[str]) -> None:
    """Emit a human-readable log line describing the selected providers."""
    gpu = [p for p in providers if p != "CPUExecutionProvider"]
    if gpu:
        logger.info(
            "Dense model ONNX providers: %s (CPU fallback: yes)",
            " → ".join(gpu),
        )
    else:
        logger.info("Dense model ONNX providers: CPUExecutionProvider (no GPU)")


class FastembedBackend(DenseBackend):
    """Dense embedding via fastembed (ONNX Runtime)."""

    def __init__(
        self,
        model_name: str,
        providers: Optional[Sequence[str]] = None,
        threads: Optional[int] = None,
    ) -> None:
        self._model_name = model_name
        self._providers = _resolve_providers(providers)
        self._threads = threads
        self._model: Optional["TextEmbedding"] = None
        self._active_provider: str = "CPUExecutionProvider"
        self._dim: Optional[int] = None

    def _ensure_loaded(self) -> "TextEmbedding":
        from fastembed import TextEmbedding

        if self._model is not None:
            return self._model

        _log_active_provider(self._providers)
        try:
            self._model = self._load(self._providers)
        except Exception as exc:
            gpu_providers = [p for p in self._providers if p != "CPUExecutionProvider"]
            if gpu_providers:
                logger.warning(
                    "GPU provider %s failed (%s). Falling back to CPUExecutionProvider.",
                    gpu_providers,
                    exc,
                )
                self._model = self._load(["CPUExecutionProvider"])
            else:
                raise

        self._active_provider = self._probe_provider(self._model)

        if self._active_provider != "CPUExecutionProvider":
            logger.info("Dense model ACTIVE provider: %s ✓", self._active_provider)
        else:
            requested_gpu = [p for p in self._providers if p != "CPUExecutionProvider"]
            if requested_gpu:
                logger.warning(
                    "Requested GPU providers %s but ONNX Runtime fell back to "
                    "CPUExecutionProvider.  Install CUDA toolkit / cuDNN or set "
                    "ONNX_PROVIDERS=CPUExecutionProvider to silence this warning.",
                    requested_gpu,
                )
            else:
                logger.info("Dense model ACTIVE provider: CPUExecutionProvider")

        return self._model

    def _load(self, providers: List[str]) -> "TextEmbedding":
        from fastembed import TextEmbedding  # noqa: F811

        kwargs = {"model_name": self._model_name, "providers": providers}
        if self._threads is not None:
            kwargs["threads"] = self._threads
        logger.info(
            "Loading dense model '%s' (fastembed/ONNX) providers=%s threads=%s",
            self._model_name,
            providers,
            self._threads,
        )
        return TextEmbedding(**kwargs)

    @staticmethod
    def _probe_provider(model: "TextEmbedding") -> str:  # type: ignore[name-defined]
        """
        Inspect the ONNX session inside a fastembed model to find which
        execution provider is *actually* being used.
        """
        try:
            session = getattr(model, "model", None)
            if session is not None:
                session = getattr(session, "model", session)
            providers = getattr(session, "get_providers", lambda: [])()
            if providers:
                return providers[0]
        except Exception:
            pass
        return "CPUExecutionProvider"

    # -- DenseBackend interface ---------------------------------------------

    def passage_embed(self, texts: List[str]) -> List[List[float]]:
        model = self._ensure_loaded()
        return [vec.tolist() for vec in model.passage_embed(texts)]

    def query_embed(self, text: str) -> List[float]:
        model = self._ensure_loaded()
        return next(model.query_embed(text)).tolist()

    def get_dimension(self) -> int:
        if self._dim is None:
            model = self._ensure_loaded()
            probe = next(model.passage_embed(["probe"]))
            self._dim = len(probe)
        return self._dim

    def get_active_provider(self) -> str:
        self._ensure_loaded()
        return self._active_provider


# ---------------------------------------------------------------------------
# sentence-transformers backend (PyTorch)
# ---------------------------------------------------------------------------


def _resolve_torch_dtype(dtype_str: Optional[str] = None):
    """
    Resolve a dtype string to a ``torch.dtype``.

    Priority order:
    1. Explicit *dtype_str* argument (from caller or ``EMBEDDING_DTYPE`` env).
    2. Auto-detect: use BF16 if the GPU supports it (Ampere+, compute
       capability ≥ 8.0), otherwise fall back to FP32.

    Supported values for *dtype_str*: ``"fp32"``, ``"fp16"``, ``"bf16"``,
    ``"float32"``, ``"float16"``, ``"bfloat16"``, ``"auto"`` (or ``None``
    for auto-detect).

    Returns
    -------
    torch.dtype
    """
    import torch

    _DTYPE_MAP = {
        "fp32": torch.float32,
        "float32": torch.float32,
        "fp16": torch.float16,
        "float16": torch.float16,
        "bf16": torch.bfloat16,
        "bfloat16": torch.bfloat16,
    }

    raw = dtype_str or os.getenv("EMBEDDING_DTYPE", "").strip().lower() or None

    if raw and raw != "auto":
        dt = _DTYPE_MAP.get(raw)
        if dt is None:
            logger.warning(
                "Unknown EMBEDDING_DTYPE '%s' — falling back to auto-detect. Valid values: %s",
                raw,
                list(_DTYPE_MAP.keys()) + ["auto"],
            )
        else:
            logger.info("Torch dtype (from config): %s", dt)
            return dt

    # Auto-detect: check BF16 support on the current CUDA device.
    if torch.cuda.is_available():
        try:
            cap = torch.cuda.get_device_capability()
            if cap[0] >= 8:
                logger.info(
                    "GPU compute capability %d.%d ≥ 8.0 — using bfloat16",
                    cap[0],
                    cap[1],
                )
                return torch.bfloat16
            else:
                logger.info(
                    "GPU compute capability %d.%d < 8.0 — bfloat16 not supported, "
                    "using float32.  Set EMBEDDING_DTYPE=fp16 to try half-precision.",
                    cap[0],
                    cap[1],
                )
                return torch.float32
        except Exception:
            pass

    # CPU or detection failed — FP32 is always safe.
    logger.info("Torch dtype (auto): float32 (CPU or detection failed)")
    return torch.float32


class SentenceTransformerBackend(DenseBackend):
    """Dense embedding via sentence-transformers (PyTorch)."""

    def __init__(
        self,
        model_name: str,
        device: Optional[str] = None,
        trust_remote_code: bool = True,
        dtype: Optional[str] = None,
    ) -> None:
        self._model_name = model_name
        self._device = device or os.getenv("EMBEDDING_DEVICE") or None
        self._trust_remote_code = trust_remote_code
        self._dtype_override = dtype
        self._model: Optional["SentenceTransformer"] = None
        self._dim: Optional[int] = None
        self._resolved_device: str = "cpu"
        self._resolved_dtype: str = "float32"

    def _ensure_loaded(self) -> "SentenceTransformer":
        if self._model is not None:
            return self._model

        try:
            from sentence_transformers import SentenceTransformer  # noqa: F811
        except ImportError as exc:
            raise ImportError(
                "sentence-transformers is required for EMBEDDING_BACKEND='sentence-transformers'. "
                "Install it with:  pip install -e '.[st]'  or  pip install sentence-transformers"
            ) from exc

        torch_dtype = _resolve_torch_dtype(self._dtype_override)
        self._resolved_dtype = str(torch_dtype).replace("torch.", "")

        logger.info(
            "Loading dense model '%s' (sentence-transformers/PyTorch) device=%s dtype=%s",
            self._model_name,
            self._device or "auto",
            self._resolved_dtype,
        )

        kwargs = {
            "model_name_or_path": self._model_name,
            "trust_remote_code": self._trust_remote_code,
            "model_kwargs": {"torch_dtype": torch_dtype},
        }
        if self._device is not None:
            kwargs["device"] = self._device

        self._model = SentenceTransformer(**kwargs)
        self._resolved_device = str(self._model.device)

        logger.info(
            "Dense model loaded: %s on device '%s' dtype=%s (dim=%d)",
            self._model_name,
            self._resolved_device,
            self._resolved_dtype,
            self._model.get_sentence_embedding_dimension(),
        )

        return self._model

    # -- DenseBackend interface ---------------------------------------------

    def passage_embed(self, texts: List[str]) -> List[List[float]]:
        model = self._ensure_loaded()
        # sentence-transformers returns a numpy array of shape (N, dim)
        embeddings = model.encode(
            texts,
            normalize_embeddings=True,
            show_progress_bar=False,
            batch_size=len(texts),
        )
        return embeddings.tolist()

    def query_embed(self, text: str) -> List[float]:
        model = self._ensure_loaded()
        embedding = model.encode(
            text,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return embedding.tolist()

    def get_dimension(self) -> int:
        if self._dim is None:
            model = self._ensure_loaded()
            dim = model.get_sentence_embedding_dimension()
            assert dim is not None, (
                f"Model {self._model_name} returned None for embedding dimension"
            )
            self._dim = dim
        return self._dim

    def get_active_provider(self) -> str:
        self._ensure_loaded()
        return f"PyTorch/{self._resolved_device} ({self._resolved_dtype})"


# ---------------------------------------------------------------------------
# Backend factory
# ---------------------------------------------------------------------------


def _create_dense_backend(
    backend: str,
    model_name: str,
    providers: Optional[Sequence[str]] = None,
    threads: Optional[int] = None,
) -> DenseBackend:
    """
    Instantiate the appropriate dense backend.

    Parameters
    ----------
    backend:
        ``"fastembed"`` or ``"sentence-transformers"``.
    model_name:
        HuggingFace model identifier.
    providers:
        ONNX providers (fastembed backend only).
    threads:
        ONNX intra-op thread count (fastembed backend only).
    """
    if backend == "sentence-transformers":
        return SentenceTransformerBackend(model_name=model_name)
    else:
        return FastembedBackend(
            model_name=model_name,
            providers=providers,
            threads=threads,
        )


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class EmbeddingManager:
    """
    Lazily-initialised wrapper around dense + sparse embedding models.

    The dense backend is selected by :data:`~crucible_indexer.config.EMBEDDING_BACKEND`
    (``"fastembed"`` for ONNX, ``"sentence-transformers"`` for PyTorch).
    The sparse backend always uses fastembed's BM25 tokeniser.

    Parameters
    ----------
    dense_model_name:
        HuggingFace model identifier for the dense encoder.
    sparse_model_name:
        HuggingFace / fastembed identifier for the sparse encoder.
    backend:
        Dense backend name.  Defaults to the config value.
    providers:
        ONNX execution providers (fastembed backend only).  ``None``
        uses auto-detected providers from config.
    threads:
        Intra-op thread count for ONNX Runtime (fastembed only).
    """

    def __init__(
        self,
        dense_model_name: str = DENSE_MODEL,
        sparse_model_name: str = SPARSE_MODEL,
        backend: str = EMBEDDING_BACKEND,
        providers: Optional[Sequence[str]] = None,
        threads: Optional[int] = ONNX_THREADS,
    ) -> None:
        self._dense_model_name = dense_model_name
        self._sparse_model_name = sparse_model_name
        self._backend_name = backend
        self._providers = _resolve_providers(providers)
        self._threads = threads

        # Lazily initialised — first access triggers model download/load.
        self._dense_backend: Optional[DenseBackend] = None
        self._sparse: Optional[SparseTextEmbedding] = None

    # -- lazy loaders -------------------------------------------------------

    @property
    def dense_backend(self) -> DenseBackend:
        """Return the dense backend, creating it on first access."""
        if self._dense_backend is None:
            self._dense_backend = _create_dense_backend(
                backend=self._backend_name,
                model_name=self._dense_model_name,
                providers=self._providers,
                threads=self._threads,
            )
        return self._dense_backend

    @property
    def dense_model(self):
        """
        Legacy accessor — returns the dense backend.

        Kept for backward compatibility with code that accessed
        ``manager.dense_model`` directly.  Prefer :attr:`dense_backend`.
        """
        return self.dense_backend

    @property
    def sparse_model(self) -> SparseTextEmbedding:
        """Return the sparse embedding model, loading it on first access.

        Note: The BM25 sparse model is a statistical tokeniser — it does
        **not** use ONNX Runtime and is unaffected by GPU settings.
        """
        if self._sparse is None:
            logger.info(
                "Loading sparse model '%s' (BM25 — CPU-only, no ONNX)", self._sparse_model_name
            )
            self._sparse = SparseTextEmbedding(self._sparse_model_name)
        return self._sparse

    @property
    def dense_vector_name(self) -> str:
        """Named-vector key used in the Qdrant collection for the dense leg."""
        return DENSE_VECTOR_NAME

    @property
    def sparse_vector_name(self) -> str:
        """Named-vector key used in the Qdrant collection for the sparse leg."""
        return SPARSE_VECTOR_NAME

    @property
    def dense_dim(self) -> int:
        """Dimensionality of the dense model (probed once and cached)."""
        return self.dense_backend.get_dimension()

    @property
    def active_provider(self) -> Optional[str]:
        """The provider/device that is actually in use (populated after first load)."""
        if self._dense_backend is None:
            return None
        return self._dense_backend.get_active_provider()

    @property
    def is_gpu(self) -> bool:
        """Return ``True`` if the dense model is running on a GPU."""
        provider = self.active_provider
        if provider is None:
            return False
        # fastembed: anything other than CPUExecutionProvider is GPU
        # sentence-transformers: "PyTorch/cuda*" is GPU
        return provider != "CPUExecutionProvider" and "cpu" not in provider.lower()

    @property
    def backend_name(self) -> str:
        """Return the name of the dense embedding backend."""
        return self._backend_name

    # -- synchronous bulk API (indexer pipeline) ----------------------------

    def embed_passages(self, texts: List[str]) -> List[HybridEmbedding]:
        """
        Embed a list of *passage* texts with both models.

        Use this for documents / code chunks that will be **stored** in
        Qdrant.  The dense backend applies passage-side pre-processing
        where supported (fastembed asymmetric; sentence-transformers
        uses symmetric encode by default).

        .. note::

           For maximum throughput, pass large batches (256+ texts).
           Both backends benefit from larger batches on GPU and CPU.
        """
        if not texts:
            return []

        dense_vecs = self.dense_backend.passage_embed(texts)
        sparse_vecs = list(self.sparse_model.embed(texts))

        results: List[HybridEmbedding] = []
        for dv, sv in zip(dense_vecs, sparse_vecs):
            values = dv if isinstance(dv, list) else dv.tolist()
            results.append(
                HybridEmbedding(
                    dense=DenseEmbedding(values=values),
                    sparse=SparseEmbeddingResult(
                        indices=sv.indices.tolist(),
                        values=sv.values.tolist(),
                    ),
                )
            )
        return results

    def embed_query(self, text: str) -> HybridEmbedding:
        """
        Embed a single *query* text with both models.

        Use this for search queries.  The dense backend applies
        query-side pre-processing where supported.
        """
        dense_vec = self.dense_backend.query_embed(text)
        sparse_vec = next(self.sparse_model.query_embed(text))

        values = dense_vec if isinstance(dense_vec, list) else dense_vec.tolist()
        return HybridEmbedding(
            dense=DenseEmbedding(values=values),
            sparse=SparseEmbeddingResult(
                indices=sparse_vec.indices.tolist(),
                values=sparse_vec.values.tolist(),
            ),
        )

    def embed_query_dense_only(self, text: str) -> DenseEmbedding:
        """Embed a query with the dense model only (for ablation / fallback)."""
        dense_vec = self.dense_backend.query_embed(text)
        values = dense_vec if isinstance(dense_vec, list) else dense_vec.tolist()
        return DenseEmbedding(values=values)

    def embed_query_sparse_only(self, text: str) -> SparseEmbeddingResult:
        """Embed a query with the sparse model only (for ablation / fallback)."""
        sparse_vec = next(self.sparse_model.query_embed(text))
        return SparseEmbeddingResult(
            indices=sparse_vec.indices.tolist(),
            values=sparse_vec.values.tolist(),
        )

    # -- async wrappers (MCP server) ----------------------------------------

    async def aembed_passages(self, texts: List[str]) -> List[HybridEmbedding]:
        """Async wrapper — runs :meth:`embed_passages` in a thread executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.embed_passages, texts)

    async def aembed_query(self, text: str) -> HybridEmbedding:
        """Async wrapper — runs :meth:`embed_query` in a thread executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.embed_query, text)
