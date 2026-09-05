"""Example custom security rule for VRA.

Copy this file into `vra/rules/<category>/` and import it in the matching
`__init__.py` to register it. A rule is a subclass of `SecurityRule` decorated
with `@RuleRegistry.register`. It implements `analyze(context)` and returns a
list of `Finding` objects.

*Always use cautious language and report a confidence value. VRA never claims
a finding is a confirmed vulnerability based on static evidence alone.*
"""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

# A pattern that triggers the rule. Use a targeted regex to limit false positives.
SUSPICIOUS_PATTERN = re.compile(r"\b(untrusted_api_call)\s*\(")


@RuleRegistry.register
class ExampleCustomRule(SecurityRule):
    name = "example-custom"
    category = "input"
    cwe = "CWE-0"  # Replace with the relevant CWE, e.g. CWE-120
    description = "Example custom rule detecting a suspicious API call"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(context.file_content.split("\n"), 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            match = SUSPICIOUS_PATTERN.search(line)
            if match:
                findings.append(
                    self._make_finding(
                        title=f"Potential suspicious call to '{match.group(1)}'",
                        severity="medium",
                        confidence=0.5,
                        file=context.file_path,
                        line=i,
                    )
                )

        return findings
