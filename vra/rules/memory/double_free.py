"""Double-free detection rule."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

FREE_PATTERNS = [
    re.compile(r"\bfree\s*\(\s*(\w+)\s*\)"),
    re.compile(r"\bFree\s*\(\s*(\w+)\s*\)"),
]


@RuleRegistry.register
class DoubleFreeRule(SecurityRule):
    name = "double-free"
    category = "memory"
    cwe = "CWE-415"
    description = "Detects potential double-free patterns"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings = []
        lines = context.file_content.split("\n")
        freed_ptrs: dict[str, list[int]] = {}

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            for pattern in FREE_PATTERNS:
                for match in pattern.finditer(line):
                    ptr_name = match.group(1)
                    if ptr_name not in freed_ptrs:
                        freed_ptrs[ptr_name] = []
                    freed_ptrs[ptr_name].append(i)

        for ptr_name, free_lines in freed_ptrs.items():
            if len(free_lines) > 1:
                intervening_reassign = False
                for j in range(free_lines[0], free_lines[-1]):
                    if j < len(lines):
                        line = lines[j]
                        if re.search(rf"{re.escape(ptr_name)}\s*=\s*(?!.*free)", line):
                            intervening_reassign = True
                            break

                if not intervening_reassign:
                    findings.append(
                        self._make_finding(
                            title=f"Potential double-free: pointer '{ptr_name}' freed at lines {free_lines}",
                            severity="medium",
                            confidence=0.45,
                            file=context.file_path,
                            line=free_lines[-1],
                        )
                    )
        return findings
