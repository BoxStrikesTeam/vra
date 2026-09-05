"""Buffer overflow detection rule."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

UNSAFE_SINKS = [
    "memcpy",
    "memmove",
    "memset",
    "strcpy",
    "strcat",
    "sprintf",
    "gets",
    "scanf",
    "sscanf",
]

SAFE_SINKS = [
    "snprintf",
    "strncpy",
    "strlcpy",
    "strlcat",
]


@RuleRegistry.register
class BufferOverflowRule(SecurityRule):
    name = "buffer-overflow"
    category = "memory"
    cwe = "CWE-120"
    description = "Detects potential buffer overflow patterns"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            for sink in UNSAFE_SINKS:
                pattern = re.compile(rf"\b{re.escape(sink)}\s*\(")
                if pattern.search(line):
                    has_size_check = False
                    for j in range(max(0, i - 10), i):
                        prev = lines[j] if j < len(lines) else ""
                        if re.search(r"if\s*\(.*sizeof|if\s*\(.*length|if\s*\(.*size|if\s*\(.*len", prev):
                            has_size_check = True
                            break

                    findings.append(
                        self._make_finding(
                            title=f"Unsafe call to '{sink}': potential buffer overflow",
                            severity="high" if not has_size_check else "low",
                            confidence=0.6 if not has_size_check else 0.3,
                            file=context.file_path,
                            line=i,
                        )
                    )
        return findings
