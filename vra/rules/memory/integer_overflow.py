"""Integer overflow detection rule."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

ARITH_OPS = re.compile(r"=\s*[^;]*\b(\w+)\s*\*\s*(\w+)\b")
ALLOC_CALLS = re.compile(r"\b(malloc|calloc|realloc|alloca)\s*\(")
_NUM_RE = re.compile(r"^\d+[uUlL]*$")


@RuleRegistry.register
class IntegerOverflowRule(SecurityRule):
    name = "integer-overflow"
    category = "memory"
    cwe = "CWE-190"
    description = "Detects potential integer overflow patterns"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            mul_match = ARITH_OPS.search(line)
            alloc_match = ALLOC_CALLS.search(line)

            if mul_match and alloc_match:
                findings.append(
                    self._make_finding(
                        title="Potential integer overflow in size calculation before allocation",
                        severity="medium",
                        confidence=0.45,
                        file=context.file_path,
                        line=i,
                    )
                )
            elif mul_match:
                for check_line in lines[max(0, i - 5) : i]:
                    if "SIZE_MAX" in check_line or "INT_MAX" in check_line or "overflow" in check_line.lower():
                        break
                else:
                    a, b = mul_match.groups()
                    if a != b and not (_NUM_RE.match(a) or _NUM_RE.match(b)):
                        findings.append(
                            self._make_finding(
                                title=f"Multiplication '{a} * {b}' without obvious overflow check",
                                severity="low",
                                confidence=0.3,
                                file=context.file_path,
                                line=i,
                            )
                        )
        return findings
