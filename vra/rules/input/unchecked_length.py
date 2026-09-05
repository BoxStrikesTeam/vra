"""Unchecked length validation rule."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

SINKS_WITH_LENGTH = re.compile(r"\b(memcpy|memmove|read|recv|recvfrom)\s*\(")


@RuleRegistry.register
class UncheckedLengthRule(SecurityRule):
    name = "unchecked-length"
    category = "input"
    cwe = "CWE-20"
    description = "Detects unchecked length parameters"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            match = SINKS_WITH_LENGTH.search(line)
            if match:
                has_validation = False
                for j in range(max(0, i - 8), i):
                    prev = lines[j] if j < len(lines) else ""
                    if re.search(r"if\s*\(.*(<|>|<=|>=|sizeof)", prev):
                        has_validation = True
                        break

                if not has_validation:
                    findings.append(
                        self._make_finding(
                            title=f"Length parameter to '{match.group(1)}' may not be validated",
                            severity="medium",
                            confidence=0.4,
                            file=context.file_path,
                            line=i,
                        )
                    )
        return findings
