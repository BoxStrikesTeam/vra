"""Structural validation for null-dereference findings (CWE-476).

Most false positives here are pointers that *are* null-checked before use, or
dereferences guarded by a prior ``if (!p)`` / ``if (p == NULL)`` branch. We
search the enclosing function body (windowed around the finding line) for such
a guard before the sink line.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome
from vra.rules.validation.memory_leak import _window

_DEREF_RE = re.compile(r"(?<!&)\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]|\.|->)")
_ASSERT_NULL = re.compile(r"assert\s*\(\s*([A-Za-z_]\w*)\s*\)")


class NullDerefValidator(SecurityValidator):
    name = "null-deref"
    categories = ("null-safety", "null_check", "pointer")
    cwes = ("CWE-476",)

    def validate(
        self, finding: Finding, source_content: str, source_dir: Path
    ) -> ValidationOutcome:
        if not source_content:
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="No source available to check for null guards.",
            )
        block = _window(source_content, finding.source.line)
        pointer = self._locate_pointer(finding, block)
        if not pointer:
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Could not identify the dereferenced pointer.",
            )

        before = _window(source_content, finding.source.line, radius=40)
        guard_re = re.compile(
            r"if\s*(?:\(|UNLIKELY\s*\()\s*[!]?\s*\(?\s*"
            + re.escape(pointer)
            + r"\s*(?:==|!=|\)|,)|if\s*[!(]\s*"
            + re.escape(pointer)
            + r"\s*\)"
        )
        if guard_re.search(before):
            return ValidationOutcome(
                verdict=ValidationResult.LIKELY_FP,
                reason=f"'{pointer}' is null-checked before use in this function.",
                indicators=[f"null guard present for '{pointer}'"],
            )

        if _ASSERT_NULL.search(before) and pointer in _ASSERT_NULL.search(before).group(0):
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason=f"'{pointer}' is guarded by assert(); depends on NDEBUG.",
            )

        return ValidationOutcome(
            verdict=ValidationResult.CONFIRMED,
            reason=f"'{pointer}' is dereferenced with no null guard before it.",
        )

    @staticmethod
    def _locate_pointer(finding: Finding, block: str) -> str | None:
        snippet = finding.source_snippet or ""
        m = _DEREF_RE.search(snippet)
        if not m:
            m = _DEREF_RE.search(block)
        return m.group(1) if m else None
