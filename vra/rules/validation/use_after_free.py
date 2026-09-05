"""Structural validation for use-after-free findings (CWE-416).

The rule engine emits one finding at the *first* dereference after a free and
records the freed pointer in the finding title (``pointer 'ptr' freed at
line N ...``). This validator re-checks that claim on the actual source:

* If the pointer was reassigned / set to NULL between the free and the flagged
  deref (ownership recovered), the finding is a FP.
* If the flagged line does not actually dereference the pointer (a bare mention,
  a second free, or an ``if (ptr)`` guard), the finding is a FP.
* Otherwise the dereference genuinely follows the free -> confirmed.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome
from vra.rules.validation.signals import deref_pattern, is_null_check

_FREE_LINE = re.compile(r"\b(?:free|delete|Free)\s*\(\s*([A-Za-z_]\w*)\s*\)")
_REASSIGN = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*(?:NULL|nullptr|0|new\s+[A-Za-z_]+)")
# rule findings carry:  "Potential use-after-free: pointer 'ptr' freed at line N ..."
_PTR_FROM_TITLE = re.compile(r"pointer '([A-Za-z_]\w*)' freed at line (\d+)")


class UseAfterFreeValidator(SecurityValidator):
    name = "use-after-free"
    categories = ("memory", "use_after_free", "resource-management")
    cwes = ("CWE-416",)

    def __init__(self, strict: bool = False):
        self.strict = strict

    def validate(
        self, finding: Finding, source_content: str, source_dir: Path
    ) -> ValidationOutcome:
        ptr, freed_line = self._extract_pointer(finding)
        if not ptr:
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Could not identify the freed pointer.",
            )

        before = self._lines_before(source_content, finding.source.line)  # source before the use
        freed_earlier = _FREE_LINE.search(before) is not None or (freed_line and freed_line < finding.source.line)

        # 1. Pointer re-assigned/NULLed after the free -> ownership recovered.
        for m in _REASSIGN.finditer(before):
            if m.group(1) == ptr:
                return self._fp(
                    f"'{ptr}' is reassigned (e.g. set to NULL) after being freed.",
                    f"'{ptr}' NULLed/reassigned post-free",
                )

        use_line = self._line_text(source_content, finding.source.line)
        derefs = deref_pattern(ptr).search(use_line) is not None
        mentions = re.search(rf"\b{re.escape(ptr)}\b", use_line) is not None

        # 2. The flagged line is a free, a pure guard, or a bare mention.
        if not derefs:
            if _FREE_LINE.search(use_line):
                return self._fp(
                    f"The flagged use of '{ptr}' is itself a free()/delete, not a dereference.",
                    f"'{ptr}' only re-freed, not used",
                )
            if mentions and is_null_check(use_line, ptr):
                return self._fp(
                    f"The flagged '{ptr}' is a null-check/guard, not a dereference.",
                    f"'{ptr}' only null-checked, not used",
                )
            if not mentions:
                return self._fp(
                    f"The flagged line does not reference '{ptr}'.",
                    f"flagged line does not reference '{ptr}'",
                )
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason=f"'{ptr}' is mentioned on the flagged line but not dereferenced.",
            )

        # 3. Genuine dereference after an earlier free.
        if freed_earlier:
            return ValidationOutcome(
                verdict=ValidationResult.CONFIRMED,
                reason=f"Usage of '{ptr}' dereferences memory freed earlier in this function.",
            )

        return ValidationOutcome(
            verdict=ValidationResult.SUSPICIOUS,
            reason="Could not confirm that memory was freed before this use.",
        )

    @staticmethod
    def _fp(reason: str, indicator: str) -> ValidationOutcome:
        return ValidationOutcome(
            verdict=ValidationResult.LIKELY_FP,
            reason=reason,
            indicators=[indicator],
        )

    @staticmethod
    def _line_text(content: str, line: int) -> str:
        lines = content.splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1]
        return ""

    @staticmethod
    def _lines_before(content: str, line: int) -> str:
        lines = content.splitlines()
        start = max(0, line - 1 - 80)
        return "\n".join(lines[start : line - 1])

    @staticmethod
    def _extract_pointer(finding: Finding) -> tuple[str | None, int | None]:
        m = _PTR_FROM_TITLE.search(finding.title or "")
        if m:
            return m.group(1), int(m.group(2))
        return None, None
