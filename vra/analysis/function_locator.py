"""Locate the enclosing C/C++ function for a given source line.

Used to enrich findings that lack a function name so that call chains and
narratives can be resolved.
"""

from __future__ import annotations

import re
from pathlib import Path

# A function body opening brace on its own line-ends, allowing a return type
# (including pointers) before the name, e.g. `char *parse_attribute(...) {`.
FUNC_START_RE = re.compile(
    r"[;}\n]\s*(?:\w[\w:<>\s]*?){0,4}?[*\s]*\b(\w+)\s*\([^;{}]*\)\s*(?:const\s*)?\{",
    re.MULTILINE,
)

_CONTROL_KEYWORDS = {"if", "while", "for", "switch", "do", "return", "else", "typedef"}

_cache: dict[str, list[tuple[int, int, str]]] = {}


def _function_ranges(file_path: Path) -> list[tuple[int, int, str]]:
    """Return list of (start_line, end_line, function_name) for a source file."""
    key = str(file_path)
    if cached := _cache.get(key):
        return cached

    ranges: list[tuple[int, int, str]] = []
    try:
        content = file_path.read_text(errors="ignore")
    except OSError:
        _cache[key] = ranges
        return ranges

    # Find candidate function bodies: an identifier followed by (...) {
    for match in FUNC_START_RE.finditer(content):
        name = match.group(1)
        if name in _CONTROL_KEYWORDS:
            continue
        match_start = match.start()

        # Compute brace depth from the matched opening brace onward.
        i = content.find("{", match_start, match_start + 200)
        if i == -1:
            continue
        depth = 1
        j = i + 1
        end_line = -1
        while j < len(content):
            ch = content[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end_line = content.count("\n", 0, j) + 1
                    break
            j += 1

        if end_line == -1:
            end_line = content.count("\n") + 1

        start_line = content.count("\n", 0, match_start) + 1
        ranges.append((start_line, end_line, name))

    _cache[key] = ranges
    return ranges


def find_function_at(file_path: Path | str, line: int) -> str:
    """Return the name of the function enclosing `line`, or empty string."""
    path = Path(file_path)
    for start, end, name in _function_ranges(path):
        if start <= line <= end:
            return name
    return ""


def clear_cache() -> None:
    _cache.clear()
