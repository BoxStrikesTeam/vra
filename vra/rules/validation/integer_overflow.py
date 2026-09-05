"""Structural validation for integer-overflow findings (CWE-190).

FP signals: an explicit ``SIZE_MAX`` / ``__INT_MAX__`` guard immediately before
the arithmetic, or a multiplication of literals. We also reward the presence of
checked arithmetic built-ins.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome
from vra.rules.validation.memory_leak import _window

_OVERFLOW_GUARD = re.compile(
    r"\b(if|while)\s*\([^)]*(SIZE_MAX|UINT_MAX|INT_MAX|LONG_MAX|LLONG_MAX|"
    r"PTRDIFF_MAX)[^)]*\)",
    re.IGNORECASE,
)
_CHECKED_ARITH = re.compile(
    r"\b(__builtin_mul_overflow|__builtin_add_overflow|__builtin_sub_overflow|"
    r"CheckOverflow|safe_mul|safe_add|MulSaturate)\b",
    re.IGNORECASE,
)


class IntegerOverflowValidator(SecurityValidator):
    name = "integer-overflow"
    categories = ("integer-safety", "integer", "arithmetic")
    cwes = ("CWE-190", "CWE-191")

    def validate(
        self, finding: Finding, source_content: str, source_dir: Path
    ) -> ValidationOutcome:
        block = _window(source_content, finding.source.line)

        if _OVERFLOW_GUARD.search(block):
            return ValidationOutcome(
                verdict=ValidationResult.LIKELY_FP,
                reason="A max-value guard precedes the arithmetic.",
                indicators=["overflow guard (SIZE_MAX/INT_MAX) present"],
            )

        if _CHECKED_ARITH.search(block):
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Checked arithmetic used; remainder depends on its result.",
            )

        snippet = finding.source_snippet or ""
        if re.search(r"\*\s*\d+\b|\d+\s*\*", snippet):
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Multiplication involves a literal; overflow unlikely from it.",
            )

        return ValidationOutcome(
            verdict=ValidationResult.CONFIRMED,
            reason="No overflow guard detected around the arithmetic.",
        )
