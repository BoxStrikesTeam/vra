"""Use-after-free detection rule.

The old implementation emitted a finding for *every* line mentioning a freshly
freed pointer, producing thousands of false positives in real codebases (free
then the variable name appearing later in unrelated lines/comments).

We now emit at most one finding per freed handle, at the first genuine
*dereference/consumption* of the pointer after its ``free()`` within the same
function scope. ``ptr = ...`` recoveries and the free/delete call itself no
longer count as uses.
"""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry
from vra.rules.validation.signals import deref_pattern, is_null_check, strip_comments

_FREE = re.compile(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)")
_FREE_CAP = re.compile(r"\bFree\s*\(\s*([A-Za-z_]\w*)\s*\)")
_IS_FREE_LINE = re.compile(r"\b(?:free|delete|Free)\s*\(")
_REASSIGN = re.compile(r"\b([A-Za-z_]\w*)\s*=")


def _freed_pointers(line: str) -> list[str]:
    ptrs = []
    for pat in (_FREE, _FREE_CAP):
        for m in pat.finditer(line):
            ptrs.append(m.group(1))
    return ptrs


@RuleRegistry.register
class UseAfterFreeRule(SecurityRule):
    name = "use-after-free"
    category = "memory"
    cwe = "CWE-416"
    description = "Detects potential use-after-free patterns"

    def analyze(self, context: RuleContext) -> list[Finding]:
        lines = context.file_content.split("\n")
        findings: list[Finding] = []
        emitted: set[tuple[str, int]] = set()

        for i, line in enumerate(lines, 1):
            clean = strip_comments(line)
            for ptr in _freed_pointers(clean):
                self._scan_for_use(lines, i, ptr, context, emitted, findings)
        return findings

    def _scan_for_use(
        self,
        lines: list[str],
        start: int,
        ptr: str,
        context: RuleContext,
        emitted: set[tuple[str, int]],
        findings: list[Finding],
    ):
        key = (ptr, start)
        if key in emitted:
            return
        pattern = deref_pattern(ptr)
        depth = 0
        end = min(start + 400, len(lines))
        for i in range(start + 1, end + 1):
            raw = lines[i - 1]
            depth += raw.count("{") - raw.count("}")
            if depth <= 0 and raw.strip().startswith("}"):
                break
            clean = strip_comments(raw)
            if not clean.strip():
                continue
            if _IS_FREE_LINE.search(clean):
                continue
            if _REASSIGN.search(clean) and re.search(rf"\b{re.escape(ptr)}\s*=", clean):
                return  # pointer recovered before any deref
            # Pure guard/comparison lines (if (!ptr) / ptr == NULL) are not uses,
            # but a line that also dereferences (ptr != NULL && ptr->x) still is.
            if not pattern.search(clean) and is_null_check(clean, ptr):
                continue
            if pattern.search(clean):
                emitted.add(key)
                findings.append(
                    self._make_finding(
                        title=(
                            f"Potential use-after-free: pointer '{ptr}' freed "
                            f"at line {start} then dereferenced"
                        ),
                        severity="medium",
                        confidence=0.5,
                        file=context.file_path,
                        line=i,
                    )
                )
                findings[-1].notes = f"freed at line {start}"
                return


def _freed_pointers(line: str) -> list[str]:
    ptrs = []
    for pat in (_FREE, _FREE_CAP):
        for m in pat.finditer(line):
            ptrs.append(m.group(1))
    return ptrs
