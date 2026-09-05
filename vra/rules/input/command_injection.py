"""Command injection detection rule (CWE-78)."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

SHELL_SINKS = re.compile(
    r"\b(system|popen|execl|execlp|execle|execv|execvp|posix_spawn|popen|wf\s*system|ShellExecute)\s*\("
)

# Variables that typically flow from user input into a command line.
USERLIKE = re.compile(
    r"\b(argv|argc|getenv|getopt|request|input|buffer|data|cmd|command|str|src|user|param|ctx|msg)\b", re.I
)

# A literal constant command (clearly not user-controlled).
LITERAL_CMD_RE = re.compile(r'(["\'])(?:[^"\'\\]|\\.|\\\\)*\1')


@RuleRegistry.register
class CommandInjectionRule(SecurityRule):
    name = "command-injection"
    category = "input"
    cwe = "CWE-78"
    description = "Detects potential OS command injection"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            if not SHELL_SINKS.search(line):
                continue

            # If the whole argument is a literal string, not user-controlled.
            # Extract the argument after the sink name.
            sink_match = SHELL_SINKS.search(line)
            after = line[sink_match.end() :]

            is_literal = LITERAL_CMD_RE.match(after.lstrip())
            has_user_variable = USERLIKE.search(line)

            if is_literal and not has_user_variable:
                continue  # shell command constant, not obviously injectable

            # A non-literal argument (concatenation, variable, formatting) is a candidate.
            if not LITERAL_CMD_RE.match(after.lstrip()):
                findings.append(
                    self._make_finding(
                        title="Potential OS command injection: shell command contains a variable or concatenation",
                        severity="high",
                        confidence=0.45,
                        file=context.file_path,
                        line=i,
                    )
                )
            elif has_user_variable:
                findings.append(
                    self._make_finding(
                        title="Potential OS command injection: user-derived data near a shell call",
                        severity="medium",
                        confidence=0.4,
                        file=context.file_path,
                        line=i,
                    )
                )
        return findings
