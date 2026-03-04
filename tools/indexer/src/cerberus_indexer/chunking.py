"""
Text chunking, content hashing, and deterministic ID generation.

These utilities are shared by both the indexer pipeline and the MCP
server's ``qdrant-store`` tool.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from cerberus_indexer.config import (
    CHUNK_OVERLAP,
    CHUNK_WORDS,
    EXCLUDE_DIRS,
    EXCLUDE_PATHS,
    INCLUDE_EXTENSIONS,
    INCLUDE_FILENAMES,
    INCLUDE_PATHS,
)
from cerberus_indexer.models import CodeChunk

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def blake2s_hex(data: bytes) -> str:
    """Return the BLAKE2s hex digest of *data*."""
    return hashlib.blake2s(data).hexdigest()


def file_hash(path: Path) -> str:
    """Return the BLAKE2s hex digest of a file (streamed in 8 KiB chunks)."""
    h = hashlib.blake2s()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Deterministic IDs
# ---------------------------------------------------------------------------


def deterministic_id(namespace: str, key: str) -> str:
    """
    Derive a stable UUID-formatted string from *(namespace, key)*.

    The first 32 hex chars of the BLAKE2s digest are used as the UUID
    hex so that the same input always produces the same point ID.  This
    lets the indexer upsert idempotently.
    """
    digest = blake2s_hex(f"{namespace}::{key}".encode())[:32]
    return str(uuid.UUID(hex=digest))


# ---------------------------------------------------------------------------
# Batching helper
# ---------------------------------------------------------------------------


def batched(iterable: Iterable, size: int):
    """Yield successive *size*-length lists from *iterable*."""
    batch: list = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


# ---------------------------------------------------------------------------
# Word-level chunking
# ---------------------------------------------------------------------------


def chunk_words(
    text: str,
    size: int = CHUNK_WORDS,
    overlap: int = CHUNK_OVERLAP,
) -> List[str]:
    """
    Split *text* into overlapping word-level windows.

    Parameters
    ----------
    text:
        Source text to chunk.
    size:
        Maximum number of words per chunk.
    overlap:
        Number of overlapping words between consecutive chunks.

    Returns
    -------
    List[str]
        Non-empty chunk strings.
    """
    words = text.split()
    chunks: List[str] = []
    step = max(1, size - overlap)
    for i in range(0, len(words), step):
        chunk = " ".join(words[i : i + size]).strip()
        if chunk:
            chunks.append(chunk)
    return chunks


# ---------------------------------------------------------------------------
# Rust-structure-aware chunking (v0.3.0)
# ---------------------------------------------------------------------------

# Structural boundary patterns — we split when any of these start a line.
_RUST_BOUNDARY_RE = re.compile(
    r"^\s*(?:"
    r"(?:///|//!)"  # doc comments (preceding a boundary)
    r"|(?:#\[(?:cfg|test|derive|allow|deny|warn|repr))"  # attributes
    r"|(?:pub\s+(?:async\s+)?(?:unsafe\s+)?fn\b)"
    r"|(?:pub\s+(?:crate|super|self|in\b[^)]+)\s*\)?\s*(?:async\s+)?(?:unsafe\s+)?fn\b)"
    r"|(?:(?:async\s+)?(?:unsafe\s+)?fn\b)"
    r"|(?:pub\s+(?:unsafe\s+)?(?:impl|struct|enum|trait|type|const|static|mod)\b)"
    r"|(?:(?:impl|struct|enum|trait|type|const|static|mod)\b)"
    r"|(?:// region:)"
    r")",
    re.MULTILINE,
)

# For extracting traceable symbol names (fn/struct/enum/trait only — used by trace).
_TRACEABLE_SYMBOL_RE = re.compile(r"(?:fn|struct|enum|trait)\s+(\w+)")

# For extracting all declared names including const/static/type/mod (used by search).
# The optional (?:mut\s+)? prevents capturing "mut" from "static mut SOMETHING".
_DECLARED_RE = re.compile(r"(?:fn|struct|enum|trait|mod|type|const|static)\s+(?:mut\s+)?(\w+)")

# For extracting call names (filter out Rust keywords and common macros).
_CALL_RE = re.compile(r"(\w+)\s*\(")
_CALL_KEYWORDS: frozenset[str] = frozenset(
    [
        "if",
        "while",
        "for",
        "match",
        "loop",
        "return",
        "let",
        "use",
        "pub",
        "mod",
        "fn",
        "impl",
        "struct",
        "enum",
        "trait",
        "type",
        "const",
        "static",
        "Some",
        "None",
        "Ok",
        "Err",
        "vec",
        "println",
        "print",
        "eprintln",
        "eprint",
        "format",
        "write",
        "writeln",
        "assert",
        "assert_eq",
        "assert_ne",
        "panic",
        "todo",
        "unimplemented",
        "unreachable",
        "dbg",
        "Box",
        "Vec",
        "String",
        "Option",
        "Result",
        # Rust attributes (captured by _CALL_RE but not function calls)
        "cfg",
        "inline",
        "derive",
        "allow",
        "deny",
        "warn",
        "repr",
        "test",
        "doc",
        "must_use",
        "feature",
        "target_os",
        "not",
        "any",
        "all",
        "link",
        "no_mangle",
        "cold",
        "track_caller",
        # Common uppercase non-call trait/type names
        "Self",
        "From",
        "Into",
        "TryFrom",
        "TryInto",
        "Default",
        "Clone",
        "Copy",
        "Debug",
        "Display",
        "Iterator",
        "IntoIterator",
    ]
)

# Subsystem detection prefixes (ordered longest-first to avoid prefix conflicts).
_SUBSYSTEM_PREFIXES: List[Tuple[str, str]] = [
    ("cerberus/kernel/", "kernel"),
    ("cerberus/runtime/", "runtime"),
    ("cerberus/crucibles/", "crucibles"),
    ("cerberus/crypto/", "crypto"),
    ("tools/", "tools"),
    ("tests/", "tests"),
    ("docs/", "docs"),
    ("library/", "library"),
]


def _derive_subsystem(file_path: str) -> str:
    """Derive the subsystem name from a repo-relative file path."""
    for prefix, subsystem in _SUBSYSTEM_PREFIXES:
        if file_path.startswith(prefix):
            return subsystem
    return ""


def _derive_crate_name(file_path: str) -> str:
    """
    Derive the crate name from a repo-relative file path.

    E.g. ``cerberus/kernel/forge-boot/src/ledgerfs_boot.rs`` → ``"forge-boot"``
    """
    parts = Path(file_path).parts
    # Look for the crate directory: it usually sits 2-3 levels deep under a
    # known workspace root (e.g. crucible/kernel/<crate>/).
    for i, part in enumerate(parts):
        if part in ("kernel", "runtime", "crucibles", "crypto") and i + 1 < len(parts):
            return parts[i + 1]
        if part == "tools" and i + 1 < len(parts):
            return parts[i + 1]
    return ""


def _derive_module_path(file_path: str) -> str:
    """
    Derive a Rust module path from a repo-relative file path.

    E.g. ``cerberus/kernel/forge-boot/src/ledgerfs_boot.rs``
         → ``"forge_boot::ledgerfs_boot"``
    """
    path = Path(file_path)
    if path.suffix != ".rs":
        return ""
    crate = _derive_crate_name(file_path)
    if not crate:
        return ""
    crate_mod = crate.replace("-", "_")
    # Build the module path from the src/ directory onwards.
    try:
        src_idx = path.parts.index("src")
        rel_parts = list(path.parts[src_idx + 1 :])
    except ValueError:
        return crate_mod
    if not rel_parts:
        return crate_mod
    # Drop lib.rs / main.rs — these are just the crate root.
    if rel_parts[-1] in ("lib.rs", "main.rs"):
        if len(rel_parts) == 1:
            return crate_mod
        rel_parts = rel_parts[:-1]
    else:
        # Strip .rs suffix from the last part.
        stem = Path(rel_parts[-1]).stem
        rel_parts = rel_parts[:-1] + [stem]
    module_parts = [p.replace("-", "_") for p in rel_parts]
    return "::".join([crate_mod] + module_parts)


def _extract_chunk_metadata(
    lines: List[str],
    file_path: str,
) -> Dict:
    """
    Extract v0.3.0 metadata from a list of source lines.

    Returns a dict with keys: symbols, kind, is_test, is_unsafe, calls,
    doc_comment.
    """
    text = "\n".join(lines)

    # Traceable symbols: only fn/struct/enum/trait — used by the trace tool.
    symbols = _TRACEABLE_SYMBOL_RE.findall(text)
    # All declared names: fn/struct/enum/trait/mod/type/const/static — used by search.
    declared = _DECLARED_RE.findall(text)

    raw_calls = _CALL_RE.findall(text)
    # Filter keywords and attributes; uppercase items that aren't real calls
    # (e.g. derive, cfg, Self) are listed in _CALL_KEYWORDS. We no longer
    # filter by c[0].isupper() because that falsely excluded legitimate
    # PascalCase constructor calls like SomeStruct(value).
    calls = [c for c in raw_calls if c not in _CALL_KEYWORDS]

    is_test = bool(re.search(r"#\[test\]|#\[cfg\(test\)\]", text))
    is_unsafe = bool(re.search(r"\bunsafe\b", text))

    # Determine kind from dominant structural keyword.
    kind_map = [
        (r"\bfn\b", "function"),
        (r"\bimpl\b", "impl"),
        (r"\bstruct\b", "struct"),
        (r"\benum\b", "enum"),
        (r"\btrait\b", "trait"),
        (r"\bmod\b", "module"),
        (r"\b(?:const|static)\b", "const"),
    ]
    if is_test:
        kind = "test"
    else:
        kinds_found = [k for pattern, k in kind_map if re.search(pattern, text)]
        if len(kinds_found) == 1:
            kind = kinds_found[0]
        elif len(kinds_found) > 1:
            kind = "mixed"
        else:
            kind = "mixed"

    # Extract leading doc comments.
    doc_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("///") or stripped.startswith("//!"):
            doc_lines.append(stripped)
        elif doc_lines:
            # Stop at first non-doc line after doc comments have started.
            break
    doc_comment = "\n".join(doc_lines)

    return {
        "symbols": symbols,
        "declared": declared,
        "kind": kind,
        "is_test": is_test,
        "is_unsafe": is_unsafe,
        "calls": calls,
        "doc_comment": doc_comment,
    }


def chunk_rust(
    text: str,
    file_path: str,
    max_words: int = CHUNK_WORDS,
) -> List[Tuple[str, int, int, Dict]]:
    """
    Split Rust source text into structure-aware chunks.

    Splits on ``fn``, ``impl``, ``struct``, ``enum``, ``trait``, ``type``,
    ``const``, ``static``, ``mod``, ``// region:`` and ``#[cfg(`` / ``#[test]``
    boundaries.  Consecutive small items (e.g. ``const`` declarations) are
    grouped until they would exceed *max_words*.

    Parameters
    ----------
    text:
        Source text of a ``.rs`` file.
    file_path:
        Repo-relative file path (used for metadata derivation).
    max_words:
        Maximum word count per chunk before splitting within a unit.

    Returns
    -------
    List[Tuple[str, int, int, Dict]]
        Each tuple is ``(chunk_text, line_start, line_end, metadata_dict)``.
        Line numbers are 0-based.
    """
    all_lines = text.splitlines()
    if not all_lines:
        return []

    # ── Identify split points ────────────────────────────────────────────────
    # A split occurs when a line matches a structural boundary.  We also
    # collect runs of leading doc-comment lines and attributes as part of the
    # next unit.
    split_points: List[int] = [0]
    i = 0
    while i < len(all_lines):
        line = all_lines[i]
        if _RUST_BOUNDARY_RE.match(line):
            # Walk back to include any preceding doc/attribute lines that
            # belong to this item (they're already inside the previous group
            # if split_point was set before them, but we want them to
            # start the new group).
            start = i
            while start > 0:
                prev = all_lines[start - 1].strip()
                if prev.startswith("///") or prev.startswith("//!") or prev.startswith("#["):
                    start -= 1
                else:
                    break
            if start > 0 and start not in split_points:
                split_points.append(start)
            elif start == 0 and 0 not in split_points:
                split_points.append(0)
        i += 1

    # Deduplicate and sort.
    split_points = sorted(set(split_points))

    # ── Build raw groups ─────────────────────────────────────────────────────
    groups: List[Tuple[List[str], int, int]] = []
    for idx, start in enumerate(split_points):
        end = split_points[idx + 1] if idx + 1 < len(split_points) else len(all_lines)
        group_lines = all_lines[start:end]
        groups.append((group_lines, start, end - 1))

    # ── Merge small adjacent groups; split oversized ones ───────────────────
    result: List[Tuple[str, int, int, Dict]] = []
    pending_lines: List[str] = []
    pending_start: int = 0
    pending_end: int = 0

    def _flush_pending() -> None:
        if not pending_lines:
            return
        chunk_text = "\n".join(pending_lines).strip()
        if chunk_text:
            meta = _extract_chunk_metadata(pending_lines, file_path)
            result.append((chunk_text, pending_start, pending_end, meta))

    for group_lines, g_start, g_end in groups:
        group_words = len(" ".join(group_lines).split())

        if group_words > max_words:
            # Flush any pending small items first.
            _flush_pending()
            pending_lines = []
            # Split oversized group with word-level chunker.
            group_text = "\n".join(group_lines)
            sub_chunks = chunk_words(group_text, max_words, max_words // 8)
            for sub in sub_chunks:
                sub_lines = sub.splitlines()
                meta = _extract_chunk_metadata(sub_lines, file_path)
                result.append((sub, g_start, g_end, meta))
        else:
            combined_words = len(" ".join(pending_lines + group_lines).split())
            if pending_lines and combined_words > max_words:
                _flush_pending()
                pending_lines = list(group_lines)
                pending_start = g_start
                pending_end = g_end
            else:
                if not pending_lines:
                    pending_start = g_start
                pending_lines.extend(group_lines)
                pending_end = g_end

    _flush_pending()

    # If nothing was produced (e.g. the file had no structural boundaries),
    # fall back to the word-level chunker.
    if not result:
        sub_chunks = chunk_words(text, max_words, max_words // 8)
        for sub in sub_chunks:
            meta = _extract_chunk_metadata(sub.splitlines(), file_path)
            result.append((sub, 0, len(all_lines) - 1, meta))

    return result


# ---------------------------------------------------------------------------
# Scope / inclusion predicates
# ---------------------------------------------------------------------------


def in_scope(path: Path, scopes: Iterable[str]) -> bool:
    """Return ``True`` if *path* starts with any of the given *scopes*."""
    path_str = str(path)
    return any(path_str.startswith(scope) for scope in scopes)


def should_index_code(path: Path) -> bool:
    """
    Decide whether a repo-relative *path* should be indexed as code.

    The decision is based on the extension/filename allow-lists and the
    directory exclude/include lists from :mod:`cerberus_indexer.config`.
    """
    if any(part in EXCLUDE_DIRS for part in path.parts):
        return False
    path_str = str(path)
    if any(path_str.startswith(ep) for ep in EXCLUDE_PATHS):
        return False
    if path.suffix not in INCLUDE_EXTENSIONS and path.name not in INCLUDE_FILENAMES:
        return False
    # Files at the repo root (no directory component) are always in scope.
    if "/" not in str(path):
        return True
    return any(str(path).startswith(p) for p in INCLUDE_PATHS)


# ---------------------------------------------------------------------------
# Code chunk collection
# ---------------------------------------------------------------------------


def collect_code_chunks(
    abs_path: Path,
    rel_file: str,
    chunk_size: int = CHUNK_WORDS,
    overlap: int = CHUNK_OVERLAP,
) -> List[CodeChunk]:
    """
    Read a source file and split it into embeddable :class:`CodeChunk` objects.

    For ``.rs`` files, uses the AST-aware :func:`chunk_rust` splitter which
    preserves structural boundaries (functions, impl blocks, structs, etc.)
    and extracts rich metadata.  All other file types fall back to the
    word-level :func:`chunk_words` splitter.

    Parameters
    ----------
    abs_path:
        Absolute path to the file on disk.
    rel_file:
        Repository-relative path string (stored in the payload).
    chunk_size:
        Word-count per chunk (used by both chunkers).
    overlap:
        Word overlap between consecutive chunks (word-level chunker only).

    Returns
    -------
    List[CodeChunk]
        One entry per chunk.  Returns an empty list if the file is too
        short (< 20 characters) to be meaningful.
    """
    text = abs_path.read_text(encoding="utf-8", errors="ignore").strip()
    if len(text) < 20:
        return []

    language = abs_path.suffix.lstrip(".") or "text"
    result: List[CodeChunk] = []

    if abs_path.suffix == ".rs":
        # AST-aware Rust chunking.
        subsystem = _derive_subsystem(rel_file)
        crate_name = _derive_crate_name(rel_file)
        module_path = _derive_module_path(rel_file)

        raw_chunks = chunk_rust(text, rel_file, chunk_size)
        total = len(raw_chunks)
        for idx, (chunk_text, line_start, line_end, meta) in enumerate(raw_chunks):
            result.append(
                CodeChunk(
                    file=rel_file,
                    chunk_index=idx,
                    total_chunks=total,
                    language=language,
                    hash=blake2s_hex(chunk_text.encode()),
                    text=chunk_text,
                    line_start=line_start,
                    line_end=line_end,
                    symbols=meta.get("symbols", []),
                    kind=meta.get("kind", "mixed"),
                    crate_name=crate_name,
                    subsystem=subsystem,
                    module_path=module_path,
                    is_test=meta.get("is_test", False),
                    is_unsafe=meta.get("is_unsafe", False),
                    calls=meta.get("calls", []),
                    declared=meta.get("declared", []),
                    doc_comment=meta.get("doc_comment", ""),
                )
            )
    else:
        # Word-level fallback for non-Rust files.
        chunks = chunk_words(text, chunk_size, overlap)
        total = len(chunks)
        for idx, chunk in enumerate(chunks):
            result.append(
                CodeChunk(
                    file=rel_file,
                    chunk_index=idx,
                    total_chunks=total,
                    language=language,
                    hash=blake2s_hex(chunk.encode()),
                    text=chunk,
                )
            )
    return result
