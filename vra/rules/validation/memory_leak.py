"""Structural validation for memory-leak findings (CWE-401).

A classic false positive: a pointer allocated with malloc/calloc is later freed
on a different path, or freed in the same function but the heuristic matched
only the allocation line. We scan the enclosing source for a ``free(...)`` (or
``realloc``/re-assignment) over the same pointer variable.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome

_ALLOC_RE = re.compile(r"\b(malloc|calloc|realloc|alloca)\s*\(")
_FREE_RE = re.compile(r"\b(free|realloc|fclose|freeaddrinfo)\s*\(\s*([A-Za-z_]\w*)\b")
_ARTIFACT = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*\b(malloc|calloc|realloc)\s*\(")


class MemoryLeakValidator(SecurityValidator):
    name = "memory-leak"
    categories = ("resource-management", "resource", "memory")
    cwes = ("CWE-401",)

    def validate(
        self, finding: Finding, source_content: str, source_dir: Path
    ) -> ValidationOutcome:
        if not source_content:
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="No source available to check the free path.",
            )
        snippet = finding.source_snippet or ""
        # Find the pointer allocated at the finding's line (from snippet if
        # present, else from a narrowed window around the finding line).
        block = _window(source_content, finding.source.line)

        alloc_m = _ARTIFACT.search(snippet or block)
        pointer = None
        if alloc_m:
            pointer = alloc_m.group(1)
        if not pointer:
            # Fall back: token before the malloc-like call on the finding line.
            line = _line_text(source_content, finding.source.line)
            am = _ALLOC_RE.search(line)
            if am:
                candidates = re.findall(r"([A-Za-z_]\w*)\s*=\s*[^;]*", line)
                pointer = candidates[0] if candidates else None

        if not pointer:
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Could not identify the allocated pointer for free-tracking.",
            )

        freed = _FREE_RE.findall(block)
        freed_vars = {v for _, v in freed}
        if pointer in freed_vars:
            return ValidationOutcome(
                verdict=ValidationResult.LIKELY_FP,
                reason=f"Pointer '{pointer}' is freed within the same function.",
                indicators=[f"'{pointer}' has a matching free() call"],
            )

        # If the pointer is re-assigned shortly after allocation (e.g. moved
        # into a container), the ownership transfers — treat as suspicious.
        re_assign = re.findall(rf"\b{re.escape(pointer)}\s*=\s*", block)
        if len(re_assign) >= 2:
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason=f"'{pointer}' is re-assigned; ownership may transfer elsewhere.",
            )

        return ValidationOutcome(
            verdict=ValidationResult.CONFIRMED,
            reason=f"'{pointer}' is allocated with no matching free() in this function.",
        )


def _line_text(content: str, line: int) -> str:
    lines = content.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1]
    return ""


def _window(content: str, line: int, radius: int = 80) -> str:
    """Return text from max(1, line-radius+1) .. line+radius lines."""
    lines = content.splitlines()
    start = max(0, line - 1 - radius)
    end = min(len(lines), line - 1 + radius + 1)
    return "\n".join(lines[start:end])
