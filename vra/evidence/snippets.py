"""Source code snippet extraction for VRA."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from vra.core.logging import get_logger

log = get_logger("evidence.snippets")

_MAX_CACHED_FILES = 500


@lru_cache(maxsize=_MAX_CACHED_FILES)
def _read_lines(path: str) -> tuple[str, ...]:
    try:
        return tuple(Path(path).read_text(errors="ignore").split("\n"))
    except OSError:
        log.debug("Failed to read %s", path)
        return ()


def extract_snippet(file_path: str, line: int, context_lines: int = 15) -> str:
    lines = _read_lines(file_path)
    if not lines:
        return ""
    start = max(0, line - context_lines - 1)
    end = min(len(lines), line + context_lines)
    snippet_lines = lines[start:end]

    result = []
    for i, code_line in enumerate(snippet_lines, start=start + 1):
        marker = ">>>" if i == line else "   "
        result.append(f"{marker} {i:4d} | {code_line}")
    return "\n".join(result)


def clear_cache() -> None:
    _read_lines.cache_clear()
