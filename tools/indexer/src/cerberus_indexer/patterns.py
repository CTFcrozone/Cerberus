"""
Pattern mining for the Cerberus indexer.

Scans Rust source files and Markdown documentation for occurrences of
the patterns defined in :data:`cerberus_indexer.models.PATTERNS`, collects
evidence snippets, and produces :class:`~cerberus_indexer.models.PatternEntry`
objects ready for embedding and upsert.
"""

from typing import Iterable, List, Tuple

from cerberus_indexer.chunking import deterministic_id, in_scope
from cerberus_indexer.config import (
    PATTERN_CODE_SCOPES,
    PATTERN_DOC_SCOPES,
    PATTERN_EXCLUDE_DIRS,
)
from cerberus_indexer.models import PATTERNS, Evidence, PatternEntry, PatternSpec

# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def find_files(
    base: Path,
    glob: str,
    allowed_scopes: Iterable[str],
    exclude_dirs: Iterable[str],
) -> List[Path]:
    """
    Walk *base* with *glob*, keeping only files whose repo-relative path
    starts with one of *allowed_scopes* and whose path parts do not
    contain any of *exclude_dirs*.

    Returns repo-relative :class:`Path` objects (relative to *base*).
    """
    exclude_set = set(exclude_dirs)
    paths: List[Path] = []
    for p in sorted(base.glob(glob)):
        if not p.is_file():
            continue
        try:
            rel = p.relative_to(base)
        except ValueError:
            continue
        if any(part in exclude_set for part in rel.parts):
            continue
        if not in_scope(rel, allowed_scopes):
            continue
        paths.append(rel)
    return paths


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------


def extract_code_evidence(
    base: Path,
    rel_path: Path,
    regex: re.Pattern[str],
) -> List[Evidence]:
    """
    Scan a single source file for lines matching *regex* and return
    :class:`Evidence` objects with the matched line plus a few lines
    of surrounding context.
    """
    abs_path = base / rel_path
    hits: List[Evidence] = []
    try:
        lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return hits

    for i, line in enumerate(lines):
        if not regex.search(line):
            continue

        # Grab the nearest preceding comment or function signature as context.
        context_line = ""
        for j in range(max(0, i - 3), i):
            stripped = lines[j].strip()
            if stripped.startswith("//") or stripped.startswith("fn "):
                context_line = stripped
                break

        hits.append(
            Evidence(
                file_path=str(rel_path),
                line_start=i + 1,
                line_end=i + 1,
                code_snippet=line.strip(),
                context=context_line,
            )
        )
    return hits


def extract_doc_snippets(
    base: Path,
    rel_path: Path,
    regex: re.Pattern[str],
    max_snippets: int = 3,
) -> List[Tuple[str, str]]:
    """
    Scan a Markdown file for lines matching *regex* and return up to
    *max_snippets* ``(file_path, snippet)`` pairs, where each snippet
    is ±2 lines of context around the match.
    """
    abs_path = base / rel_path
    snippets: List[Tuple[str, str]] = []
    try:
        lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return snippets

    for i, line in enumerate(lines):
        if not regex.search(line):
            continue
        start = max(0, i - 2)
        end = min(len(lines), i + 3)
        snippet = "\n".join(lines[start:end]).strip()
        snippets.append((str(rel_path), snippet))
        if len(snippets) >= max_snippets:
            break
    return snippets


# ---------------------------------------------------------------------------
# Pattern mining entry point
# ---------------------------------------------------------------------------


def mine_patterns(
    base: Path,
    specs: List[PatternSpec] | None = None,
) -> List[PatternEntry]:
    """
    Mine the repository at *base* for all patterns in *specs*.

    Parameters
    ----------
    base:
        Absolute path to the repository root.
    specs:
        Pattern specifications to search for.  Defaults to the built-in
        :data:`~crucible_indexer.models.PATTERNS` table.

    Returns
    -------
    List[PatternEntry]
        One entry per pattern spec, each carrying collected evidence and
        a deterministic ``pattern_id``.
    """
    if specs is None:
        specs = PATTERNS

    # Discover files once (relative to base).
    code_files = find_files(base, "**/*.rs", PATTERN_CODE_SCOPES, PATTERN_EXCLUDE_DIRS)
    doc_files = find_files(base, "**/*.md", PATTERN_DOC_SCOPES, PATTERN_EXCLUDE_DIRS)

    entries: List[PatternEntry] = []

    for spec in specs:
        code_re = re.compile(spec.code_regex)
        doc_re = re.compile(spec.doc_regex, re.IGNORECASE)

        # Collect code evidence.
        evidence: List[Evidence] = []
        for rel_path in code_files:
            if not in_scope(rel_path, spec.scopes):
                continue
            evidence.extend(extract_code_evidence(base, rel_path, code_re))

        # Collect documentation snippets.
        doc_hits: List[Tuple[str, str]] = []
        for rel_path in doc_files:
            if not in_scope(rel_path, spec.scopes):
                continue
            doc_hits.extend(extract_doc_snippets(base, rel_path, doc_re))

        origin_path, snippet = ("", "")
        if doc_hits:
            origin_path, snippet = doc_hits[0]

        pid = deterministic_id(
            "pattern",
            f"{spec.name}::{origin_path or 'none'}::{','.join(sorted(set(spec.scopes)))}",
        )
        timestamp = datetime.now(timezone.utc).isoformat()
        confidence = 1.0 if evidence else 0.5

        entries.append(
            PatternEntry(
                pattern_id=pid,
                pattern_name=spec.name,
                origin_path=origin_path,
                snippet=snippet,
                reason=spec.reason,
                tags=spec.tags,
                scope_paths=spec.scopes,
                evidence=evidence,
                timestamp=timestamp,
                confidence=confidence,
            )
        )

    return entries
