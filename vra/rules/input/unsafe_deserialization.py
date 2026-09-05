"""Unsafe deserialization detection rule."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

DESERIALIZATION_SINKS = re.compile(r"\b(eval|system|exec|popen|dlopen|dlsym)\s*\(")


@RuleRegistry.register
class UnsafeDeserializationRule(SecurityRule):
    name = "unsafe-deserialization"
    category = "input"
    cwe = "CWE-502"
    description = "Detects unsafe deserialization patterns"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            match = DESERIALIZATION_SINKS.search(line)
            if match:
                findings.append(
                    self._make_finding(
                        title=f"Potentially dangerous call to '{match.group(1)}'",
                        severity="high",
                        confidence=0.5,
                        file=context.file_path,
                        line=i,
                    )
                )
        return findings
