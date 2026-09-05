"""Structural validation for buffer-overflow / unsafe-copy findings (CWE-120).

The recurring FP: a ``strcpy``/``memcpy`` flagged anywhere in a large project
without a taint path, or a guarded copy being reported. We reward size-bounding
variants and demote raw copies that lack any attacker-relevant root; a raw copy
fed by tracked attacker data stays confirmed.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome
from vra.rules.validation.memory_leak import _line_text, _window
from vra.rules.validation.signals import (
    ambient_only,
    attacker_root,
    low_controllability,
    strip_comments,
)

_RAW_COPY = re.compile(
    r"\b(strcpy|strcat|sprintf|wcscpy|vsprintf|gets|scanf)\s*\(",
    re.IGNORECASE,
)
_BOUNDED_COPY = re.compile(
    r"\b(strncpy|strncat|snprintf|bcopy|memcpy_s|strlcpy|strlcat|vsnprintf|"
    r"memcpy|memmove|heap-buffer-overflow|__builtin___memcpy_chk)\s*\(",
    re.IGNORECASE,
)
_SIZE_GUARD = re.compile(
    r"\bif\s*\([^)]*(?:<=|>=|<|>)\s*[^)]*\)|\b(?:sizeof|strlen|strnlen)\s*\(",
)


class BufferOverflowValidator(SecurityValidator):
    name = "buffer-overflow"
    categories = ("input", "memory", "buffer", "string")
    cwes = ("CWE-120", "CWE-121", "CWE-122")

    def __init__(self, strict: bool = False):
        self.strict = strict

    def validate(
        self, finding: Finding, source_content: str, source_dir: Path
    ) -> ValidationOutcome:
        block = strip_comments(_window(source_content, finding.source.line))
        line = strip_comments(_line_text(source_content, finding.source.line))
        snippet = finding.source_snippet or ""
        taint_path = bool(finding.dataflow)
        ctrl_low = low_controllability(finding)
        root_attacker = attacker_root(finding)
        ambient = ambient_only(finding)

        bounded = _BOUNDED_COPY.search(snippet + "\n" + line)
        raw = _RAW_COPY.search(snippet + "\n" + line)

        # Size-bounding variants: safe if the size argument is correct.
        if bounded and not raw:
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Copy uses a size-bounding variant; safe if size is correct.",
            )

        if raw:
            guard = _SIZE_GUARD.search(block)
            # Raw unbounded copy with no provenance and no guard -> demote.
            if (not taint_path and ctrl_low) or ambient:
                return self._fp(
                    "Unbounded copy reported without attacker-relevant input.",
                    "copy not tied to attacker-controlled data",
                )
            if self.strict and not root_attacker and taint_path:
                return self._fp(
                    "Copy is rooted only in ambient/non-attacker data.",
                    "copy not tied to attacker-controlled data",
                )
            if root_attacker and not guard:
                return ValidationOutcome(
                    verdict=ValidationResult.CONFIRMED,
                    reason="Unbounded copy with no visible size guard in context.",
                )
            if guard:
                return ValidationOutcome(
                    verdict=ValidationResult.SUSPICIOUS,
                    reason="A size guard exists; runtime value determines safety.",
                )

        return ValidationOutcome(
            verdict=ValidationResult.SUSPICIOUS,
            reason="Copy safety depends on runtime values; cannot dismiss.",
        )

    @staticmethod
    def _fp(reason: str, indicator: str) -> ValidationOutcome:
        return ValidationOutcome(
            verdict=ValidationResult.LIKELY_FP,
            reason=reason,
            indicators=[indicator],
        )
