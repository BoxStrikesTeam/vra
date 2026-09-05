"""Memory leak detection rule."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

ALLOC_CALLS = re.compile(r"\b(malloc|calloc|realloc|strdup|open|fopen|socket)\s*\(")
FREE_CALLS = re.compile(r"\b(free|fclose|close)\s*\(")


@RuleRegistry.register
class MemoryLeakRule(SecurityRule):
    name = "memory-leak"
    category = "memory"
    cwe = "CWE-401"
    description = "Detects potential memory/resource leaks"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings = []
        lines = context.file_content.split("\n")
        allocated: dict[str, int] = {}
        freed: set[str] = set()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            alloc_match = ALLOC_CALLS.search(line)
            if alloc_match:
                var_match = re.search(r"(\w+)\s*=\s*\w+\s*\(", line)
                if var_match:
                    allocated[var_match.group(1)] = i

            free_match = FREE_CALLS.search(line)
            if free_match:
                var_match = re.search(r"free\s*\(\s*(\w+)", line)
                if var_match:
                    freed.add(var_match.group(1))

        for var_name, alloc_line in allocated.items():
            if var_name not in freed:
                findings.append(
                    self._make_finding(
                        title=f"Potential memory leak: '{var_name}' allocated at line {alloc_line} but no matching free found",  # noqa: E501
                        severity="low",
                        confidence=0.35,
                        file=context.file_path,
                        line=alloc_line,
                    )
                )
        return findings
