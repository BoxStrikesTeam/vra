"""Structural validation for allocation-size overflow findings (CWE-120 / CWE-190).

These come from the taint engine's ``alloc_overflow`` sink. A report of
``malloc(a*b)`` is only interesting when at least one factor is attacker
controlled. We demote on literal factors, ambient-only taint roots, or (in
strict mode) the complete absence of an attacker-relevant root.
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
    low_controllability,
)

_IS_ALLOC = re.compile(r"\b(malloc|calloc|realloc|kmalloc|kzalloc|vmalloc)\s*\(")
_LITERAL_ONLY = re.compile(r"^\s*[A-Za-z_]\w*\s*\*\s*\d+\s*$|^\s*\d+\s*\*\s*\d+\s*$")
# a variable multiplied by a literal, within the same alloc expression
_NUM_FACTOR = re.compile(r"[A-Za-z_]\w*\s*\*\s*\d+|\d+\s*\*\s*[A-Za-z_]\w*")

_LITERAL_IND = "multiplication factors are numeric literals, not inputs"
_CONST_IND = "allocation factors are local constants, not attacker inputs"


class AllocOverflowValidator(SecurityValidator):
    name = "alloc-overflow"
    categories = ("taint", "integer-safety", "memory")
    cwes = ("CWE-120", "CWE-190", "CWE-195")

    def __init__(self, strict: bool = False):
        self.strict = strict

    def validate(
        self, finding: Finding, source_content: str, source_dir: Path
    ) -> ValidationOutcome:
        snippet = finding.source_snippet or ""
        line = _line_text(source_content, finding.source.line)
        if not _IS_ALLOC.search(snippet + "\n" + line):
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Finding does not target an allocation site; skipping.",
            )

        taint_path = bool(finding.dataflow)
        ctrl_low = low_controllability(finding)
        root_attacker = attacker_root(finding)
        ambient = ambient_only(finding)

        # Both factors numeric literals: no attacker influence by definition.
        if _LITERAL_ONLY.search(line) and (not taint_path or ctrl_low or ambient):
            return self._fp(
                "Allocation size uses only literal factors on the allocation line.",
                _LITERAL_IND,
            )

        # One factor is a literal/constant while the taint root is ambient or
        # absent -> the "controlled" factor is not attacker data.
        if _NUM_FACTOR.search(line) and (ambient or (not taint_path and ctrl_low)):
            return self._fp(
                "Allocation factors are local/constant, not attacker-controlled.",
                _CONST_IND,
            )

        if taint_path and ambient:
            return self._fp(
                "Size taint is ambient-only (cli/config), not attacker input.",
                _CONST_IND,
            )

        if self.strict and taint_path and not root_attacker and ctrl_low:
            return self._fp(
                "No attacker-relevant source roots the allocation size arithmetic.",
                "alloc factors not attacker-controlled",
            )

        if root_attacker and taint_path:
            return ValidationOutcome(
                verdict=ValidationResult.CONFIRMED,
                reason="Size arithmetic is influenced by tracked attacker data.",
            )

        if not taint_path and ctrl_low:
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="No dataflow connects input to the multiplication.",
            )

        return ValidationOutcome(
            verdict=ValidationResult.SUSPICIOUS,
            reason="Allocation size arithmetic could not be dismissed.",
        )

    @staticmethod
    def _fp(reason: str, indicator: str) -> ValidationOutcome:
        return ValidationOutcome(
            verdict=ValidationResult.LIKELY_FP,
            reason=reason,
            indicators=[indicator],
        )
