"""Time-of-check to time-of-use (TOCTOU) detection rule (CWE-367)."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

# Check-before-use file functions.
CHECK_FNS = re.compile(r"\b(access|stat|lstat|stat64|fstat|exists|is_readable|is_writable)\s*\(")
# Use functions that should immediately follow the check for the same path.
USE_FNS = re.compile(r"\b(open|creat|fopen|openat|unlink|remove|rename|mkstemp|chmod|chown)\s*\(")


@RuleRegistry.register
class ToctouRule(SecurityRule):
    name = "toctou"
    category = "logic"
    cwe = "CWE-367"
    description = "Detects potential time-of-check to time-of-use race"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            if not CHECK_FNS.search(line):
                continue

            # Heuristic: a check on a path less than a handful of lines before a
            # use of the same path indicates a TOCTOU pattern.
            check_var = _extract_arg(line)
            if not check_var:
                continue

            for j in range(i, min(i + 15, len(lines) + 1)):
                use_line = lines[j - 1]
                if re.search(rf"\b{re.escape(check_var)}\b", use_line) and USE_FNS.search(use_line):
                    findings.append(
                        self._make_finding(
                            title=f"Potential TOCTOU: file '{check_var}' checked then used without synchronization",
                            severity="medium",
                            confidence=0.5,
                            file=context.file_path,
                            line=i,
                        )
                    )
                    break
        return findings


def _extract_arg(line: str) -> str:
    m = CHECK_FNS.search(line)
    if not m:
        return ""
    # The pattern already consumes the opening paren, so capture the argument.
    arg_match = re.search(r"^\s*([^,)]+)", line[m.end() :])
    if not arg_match:
        return ""
    arg = arg_match.group(1).strip()
    arg = arg.strip("\"'")
    # Take a plain identifier or a quoted path; skip complex expressions.
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*|/[^\s'\"]*", arg):
        return arg
    return ""
