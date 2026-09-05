"""Structural validation for unchecked-return findings (CWE-252).

The rule flags bare ``open()``/``read()``/... statements whose result is not
checked on the same line. Most false positives either consume the result on an
immediately following line or come from low-risk probe calls. We demote those;
setuid/setgid/network-binding calls stay suspicious unless truly consumed.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome
from vra.rules.validation.memory_leak import _window
from vra.rules.validation.signals import strip_comments

_RISKY = re.compile(
    r"\b(malloc|calloc|realloc|open|fopen|socket|read|write|connect|bind|listen|accept|setuid|setgid)\s*\("
)
# heuristics: result consumed on a following line
_CONSUMED = re.compile(
    r"\b(?:if|while)\s*\([^)]*(?:==|!=|<|>)\s*[^)]*\)|"
    r"\b(?:r\w*)\s*[!=]=\s*-?\d+\b|"
    r"\b(?:err|rc|ret|res|status)\w*\s*=\s*\w+\s*\(",
    re.IGNORECASE,
)
_PRIV_CALL = re.compile(r"\b(setuid|setgid|connect|bind|listen|accept)\s*\(")


class ResourceResultValidator(SecurityValidator):
    name = "resource-result"
    categories = ("logic", "resource", "resource-management")
    cwes = ("CWE-252",)

    def __init__(self, strict: bool = False):
        self.strict = strict

    def validate(self, finding: Finding, source_content: str, source_dir: Path) -> ValidationOutcome:
        block = strip_comments(_window(source_content, finding.source.line, radius=6))
        m = _RISKY.search(finding.source_snippet or "")
        if not m:
            m = _RISKY.search(block)
        call = m.group(1).lower() if m else ""

        if _CONSUMED.search(block):
            return self._fp(
                "The return value is consumed/checked shortly after the call.",
                "return value consumed or checked nearby",
            )

        # Reading/writing probes and allocations whose failure is non-fatal.
        if call in ("malloc", "calloc", "realloc", "read", "write", "open", "fopen", "socket"):
            if self.strict or _PRIV_CALL.search(block) is None:
                return self._fp(
                    f"Unchecked '{call}' result is a non-fatal probe/allocation here.",
                    "low-risk unchecked call",
                )

        if _PRIV_CALL.search(block):  # privilege/IPC change: real concern
            return ValidationOutcome(
                verdict=ValidationResult.CONFIRMED,
                reason="Privilege/IPC call result is not checked.",
            )

        return ValidationOutcome(
            verdict=ValidationResult.SUSPICIOUS,
            reason="Return value handling cannot be proven from static evidence.",
        )

    @staticmethod
    def _fp(reason: str, indicator: str) -> ValidationOutcome:
        return ValidationOutcome(
            verdict=ValidationResult.LIKELY_FP,
            reason=reason,
            indicators=[indicator],
        )
