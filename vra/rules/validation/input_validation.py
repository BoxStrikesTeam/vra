"""Structural validation for untrusted-input findings (CWE-20).

The rule flags ``getenv/argv/stdin`` values that reach a sensitive sink within
15 lines. Most false positives use a size-bounding copy variant or length-check
the value before use. We demote those; a genuinely attacker-rooted flow into an
unbounded sink stays suspicious/confirmed per the other buffer validators.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome
from vra.rules.validation.memory_leak import _window
from vra.rules.validation.signals import ambient_only, strip_comments

_BOUNDED_SINK = re.compile(
    r"\b(strncpy|strncat|snprintf|vsnprintf|memcpy_s|strlcpy|strlcat|memcpy|bcopy)\s*\(",
    re.IGNORECASE,
)
_LENGTH_CHECK = re.compile(
    r"\b(?:strnlen|strlen|sizeof|strnlen)\s*\(|"
    r"\bif\s*\([^)]*(?:<|>|<=|>=)\s*[^)]*\)",
)


class InputValidationValidator(SecurityValidator):
    name = "input-validation"
    categories = ("input", "untrusted", "validation")
    cwes = ("CWE-20",)

    def __init__(self, strict: bool = False):
        self.strict = strict

    def validate(self, finding: Finding, source_content: str, source_dir: Path) -> ValidationOutcome:
        block = strip_comments(_window(source_content, finding.source.line, radius=20))

        if ambient_only(finding):
            return self._fp(
                "Untrusted-input taint is ambient-only (cli/config), not attacker data.",
                "untrusted-input flow is ambient-only",
            )

        if _BOUNDED_SINK.search(block) and _LENGTH_CHECK.search(block):
            return self._fp(
                "The value reaches a size-bounding sink and is length-checked.",
                "input length-checked before bounded sink",
            )

        if self.strict and not finding.dataflow:
            return self._fp(
                "No attacker-relevant dataflow ties this value to user input.",
                "no attacker provenance for untrusted value",
            )

        return ValidationOutcome(
            verdict=ValidationResult.SUSPICIOUS,
            reason="Input validation state cannot be proven from static evidence.",
        )

    @staticmethod
    def _fp(reason: str, indicator: str) -> ValidationOutcome:
        return ValidationOutcome(
            verdict=ValidationResult.LIKELY_FP,
            reason=reason,
            indicators=[indicator],
        )
