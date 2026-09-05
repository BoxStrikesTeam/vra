"""Structural validation for format-string findings (CWE-134).

The rule flags ``printf(fmt_var, ...)`` where the first argument is not a string
literal. In mature codebases almost all such formats are compile-time constants
passed through variables, macros or message tables. We demote those and only
keep attacker-rooted (or unprovable) formats.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome
from vra.rules.validation.memory_leak import _line_text
from vra.rules.validation.signals import (
    ambient_only,
    attacker_root,
    strip_comments,
)

_PRINTF = re.compile(
    r"\b(?:printf|vprintf|sprintf|vsprintf|fprintf|vfprintf|snprintf|vsnprintf|syslog)\s*\(\s*([^,)]+)",
    re.IGNORECASE,
)
_CONST_FMT = re.compile(r"^[A-Z][A-Z0-9_]*$|^\"[^\"]*\"$|^[A-Za-z_]\w*\.[a-z]+$|^ctx->")


class FormatStringValidator(SecurityValidator):
    name = "format-string"
    categories = ("input", "format")
    cwes = ("CWE-134",)

    def __init__(self, strict: bool = False):
        self.strict = strict

    def validate(self, finding: Finding, source_content: str, source_dir: Path) -> ValidationOutcome:
        line = strip_comments(_line_text(source_content, finding.source.line))
        m = _PRINTF.search(line)
        fmt = (m.group(1) if m else "").strip()

        if attacker_root(finding):
            return ValidationOutcome(
                verdict=ValidationResult.CONFIRMED,
                reason="Format argument is influenced by tracked attacker data.",
            )

        if ambient_only(finding):
            return self._fp(
                "Format argument taint is ambient-only (cli/config), not attacker input.",
                "format argument is ambient-only",
            )

        if fmt and _CONST_FMT.search(fmt):
            return self._fp(
                f"Format argument '{fmt}' is a constant/macro/static format.",
                "format argument is a constant/macro",
            )

        if self.strict and not finding.dataflow:
            return self._fp(
                "No dataflow ties the format argument to attacker input.",
                "format argument has no attacker provenance",
            )

        return ValidationOutcome(
            verdict=ValidationResult.SUSPICIOUS,
            reason="Format argument origin cannot be dismissed from static evidence.",
        )

    @staticmethod
    def _fp(reason: str, indicator: str) -> ValidationOutcome:
        return ValidationOutcome(
            verdict=ValidationResult.LIKELY_FP,
            reason=reason,
            indicators=[indicator],
        )
