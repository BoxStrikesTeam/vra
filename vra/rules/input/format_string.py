"""Format string vulnerability detection rule (CWE-134)."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

# printf-family functions where the format string is the first argument.
PRINTF_SINKS = re.compile(
    r"\b(printf|vprintf|sprintf|vsprintf|fprintf|vfprintf|snprintf|vsnprintf|syslog|fprintf)\s*\("
)

# A literal format string (something with % directives or a quoted literal).
LITERAL_FORMAT_RE = re.compile(r'(["\'])(?:[^"\']*?%[^"\']*?)?\1\s*,')

# Expressions that are clearly not a user-controlled format string (constant /
# recognized safe-looking values).
SAFE_FORMAT_RE = re.compile(
    r'(["\'])(?:.*?%[dixuofeEgGcs%privatexXsp]*).*\1\s*,',
    re.IGNORECASE,
)


@RuleRegistry.register
class FormatStringRule(SecurityRule):
    name = "format-string"
    category = "input"
    cwe = "CWE-134"
    description = "Detects potential format string vulnerabilities"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            if not PRINTF_SINKS.search(line):
                continue

            # printf(user_controlled) -> first arg is not a quoted literal.
            if SAFE_FORMAT_RE.search(line):
                continue  # a literal/constant format string; safe.

            # Heuristic: a printf-like call whose first argument is not a string
            # literal is a candidate format-string issue.
            if LITERAL_FORMAT_RE.search(line):
                continue

            findings.append(
                self._make_finding(
                    title="Potential format string vulnerability: format argument is not a constant string",
                    severity="high",
                    confidence=0.5,
                    file=context.file_path,
                    line=i,
                )
            )
        return findings
