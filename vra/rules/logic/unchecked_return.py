"""Unchecked return value detection rule."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

RISKY_CALLS = re.compile(
    r"\b(malloc|calloc|realloc|open|fopen|socket|read|write|connect|bind|listen|accept|setuid|setgid)\s*\("
)


@RuleRegistry.register
class UncheckedReturnRule(SecurityRule):
    name = "unchecked-return"
    category = "logic"
    cwe = "CWE-252"
    description = "Detects unchecked return values"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("if") or stripped.startswith("while"):
                continue

            match = RISKY_CALLS.search(line)
            if match:
                has_return_check = "=" in line or "if" in line
                if not has_return_check:
                    findings.append(
                        self._make_finding(
                            title=f"Unchecked return value from '{match.group(1)}'",
                            severity="low",
                            confidence=0.35,
                            file=context.file_path,
                            line=i,
                        )
                    )
        return findings
