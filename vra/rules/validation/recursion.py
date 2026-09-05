"""Structural validation for unbounded-recursion findings (CWE-674).

The rule flags self-recursive functions with no comparison guard anywhere in
the body. Most are bounded walks (linked lists, tree nodes, depth-limited) that
terminate on data rather than a loop counter. We demote when the surrounding
function shows termination evidence (depth/limit tracking, NULL-guided walk,
explicit count comparisons).
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome
from vra.rules.validation.memory_leak import _window
from vra.rules.validation.signals import strip_comments

_DEPTH_SIGNAL = re.compile(
    r"\b(depth|level|recursion(?:_depth)?|remaining|limit|max(?:_?depth)?|count)\b\s*[:,+\-<>=/(]|"
    r"\b(MAX_)?DEPTH\b|\bNEST\b",
    re.IGNORECASE,
)
_TERMINATION = re.compile(
    r"\bif\s*\([^)]*(?:==|!=|<|>|<=|>=)\s*[^)]*\)\s*\{?\s*return|"
    r"\b(?:next|right|left|child|link)\s*(?:->|\.)?\w*\s*!=?\s*NULL?\b",
    re.IGNORECASE,
)


class RecursionValidator(SecurityValidator):
    name = "recursion"
    categories = ("logic", "recursion", "stack-recursion")
    cwes = ("CWE-674",)

    def __init__(self, strict: bool = False):
        self.strict = strict

    def validate(self, finding: Finding, source_content: str, source_dir: Path) -> ValidationOutcome:
        block = strip_comments(_window(source_content, finding.source.line, radius=60))

        if _DEPTH_SIGNAL.search(block) and _TERMINATION.search(block):
            return self._fp(
                "Recursion is depth/termination-guarded within the function.",
                "recursion bounded by depth/termination guard",
            )
        if _TERMINATION.search(block):
            return self._fp(
                "Recursive walk terminates on a NULL/end-of-structure condition.",
                "recursion terminates on structure end",
            )
        if _DEPTH_SIGNAL.search(block):
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Depth/level tracking present; bound depends on runtime data.",
            )

        return ValidationOutcome(
            verdict=ValidationResult.SUSPICIOUS,
            reason="Recursion bound cannot be proven; manual review required.",
        )

    @staticmethod
    def _fp(reason: str, indicator: str) -> ValidationOutcome:
        return ValidationOutcome(
            verdict=ValidationResult.LIKELY_FP,
            reason=reason,
            indicators=[indicator],
        )
