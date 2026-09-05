"""Untrusted input detection rule."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

TRUSTED_FUNCTIONS = re.compile(r"\b(getenv|argv|stdin|fgets|read)\s*\(")


@RuleRegistry.register
class UntrustedInputRule(SecurityRule):
    name = "untrusted-input"
    category = "input"
    cwe = "CWE-20"
    description = "Detects usage of untrusted input sources"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            match = TRUSTED_FUNCTIONS.search(line)
            if match:
                var_match = re.search(r"(\w+)\s*=", line)
                if var_match:
                    var_name = var_match.group(1)
                    used_in_sink = False
                    for j in range(i, min(i + 15, len(lines))):
                        next_line = lines[j]
                        if re.search(rf"\b{re.escape(var_name)}\b", next_line):
                            if re.search(r"\b(memcpy|strcpy|sprintf|system|exec|eval)\b", next_line):
                                used_in_sink = True
                                break

                    if used_in_sink:
                        findings.append(
                            self._make_finding(
                                title=f"Untrusted input '{var_name}' from '{match.group(1)}' reaches sensitive sink",
                                severity="medium",
                                confidence=0.5,
                                file=context.file_path,
                                line=i,
                            )
                        )
        return findings
