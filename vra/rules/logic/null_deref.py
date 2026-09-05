"""Null dereference detection rule."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

ALLOC_CALLS = re.compile(r"\b(malloc|calloc|realloc|strdup|fopen|socket)\s*\(")


@RuleRegistry.register
class NullDerefRule(SecurityRule):
    name = "null-deref"
    category = "logic"
    cwe = "CWE-476"
    description = "Detects potential null pointer dereference"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            alloc_match = ALLOC_CALLS.search(line)
            if alloc_match:
                var_match = re.search(r"(\w+)\s*=\s*\w+\s*\(", line)
                if var_match:
                    var_name = var_match.group(1)
                    has_null_check = False
                    for j in range(i, min(i + 5, len(lines))):
                        next_line = lines[j]
                        if re.search(
                            rf"if\s*\(\s*{re.escape(var_name)}\s*(!=|==\s*NULL|\bnot\s+null)",
                            next_line,
                        ):
                            has_null_check = True
                            break
                        if re.search(rf"if\s*\(\s*!{re.escape(var_name)}", next_line):
                            has_null_check = True
                            break

                    if not has_null_check:
                        findings.append(
                            self._make_finding(
                                title=f"Potential null dereference: '{var_name}' from '{alloc_match.group(1)}' not checked",  # noqa: E501
                                severity="medium",
                                confidence=0.4,
                                file=context.file_path,
                                line=i,
                            )
                        )
        return findings
