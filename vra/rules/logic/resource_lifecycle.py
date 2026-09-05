"""Resource lifecycle detection rule."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

RESOURCE_PAIRS = {
    "open": "close",
    "fopen": "fclose",
    "socket": "close",
}


@RuleRegistry.register
class ResourceLifecycleRule(SecurityRule):
    name = "resource-lifecycle"
    category = "logic"
    cwe = "CWE-404"
    description = "Detects resource lifecycle issues"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings = []
        lines = context.file_content.split("\n")
        opened: dict[str, int] = {}
        closed: set[str] = set()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            for alloc, release in RESOURCE_PAIRS.items():
                if re.search(rf"\b{re.escape(alloc)}\s*\(", line):
                    var_match = re.search(r"(\w+)\s*=", line)
                    if var_match:
                        opened[var_match.group(1)] = i

                if re.search(rf"\b{re.escape(release)}\s*\(", line):
                    var_match = re.search(rf"{re.escape(release)}\s*\(\s*(\w+)", line)
                    if var_match:
                        closed.add(var_match.group(1))

        for var_name, open_line in opened.items():
            if var_name not in closed:
                findings.append(
                    self._make_finding(
                        title=f"Potential resource leak: '{var_name}' opened at line {open_line} but not explicitly closed",  # noqa: E501
                        severity="low",
                        confidence=0.35,
                        file=context.file_path,
                        line=open_line,
                    )
                )
        return findings
