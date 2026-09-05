"""Race condition detection rule (CWE-362)."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

SIGNAL_HANDLER_RE = re.compile(r"\bsignal\s*\(\s*[A-Za-z0-9_]+,\s*(\w+)\s*\)", re.I)
SIGNAL_DECL_RE = re.compile(r"static\s+.*\b(void|int)\s+(\w+)\s*\(\s*int\s*\)")

# Functions that are not async-signal-safe when called from a signal handler.
NOT_SIGNAL_SAFE = re.compile(
    r"\b(malloc|free|printf|fprintf|sprintf|snprintf|strcpy|strcat|memcpy|"
    r"memmove|strlen|strcmp|strdup|fopen|open|read|write|close|fclose|getenv|"
    r"mutex_lock|pthread_mutex_lock|lock|unlock|exit|abort|getcwd|realpath|realloc)\s*\("
)


@RuleRegistry.register
class RaceConditionRule(SecurityRule):
    name = "race-condition"
    category = "logic"
    cwe = "CWE-362"
    description = "Detects potential races involving signal handlers and shared state"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.file_content.split("\n")
        handlers: list[str] = []

        # Collect names of functions registered as signal handlers.
        for i, line in enumerate(lines, 1):
            m = SIGNAL_HANDLER_RE.search(line)
            if m:
                handlers.append(m.group(1))
            m2 = SIGNAL_DECL_RE.search(line)
            if m2:
                handlers.append(m2.group(2))

        handler_set = set(handlers)
        if not handler_set:
            return findings

        # Find body ranges of each handler function and scan for unsafe calls.
        for h in handler_set:
            body_start, body_end, def_line = _find_function_body("\n".join(lines), h)
            if body_start is None:
                continue
            body_text = context.file_content[body_start:body_end]
            for match in NOT_SIGNAL_SAFE.finditer(body_text):
                span_line = _offset_to_line(context.file_content, body_start + match.start())
                findings.append(
                    self._make_finding(
                        title=(
                            f"Potential race/async-signal-safety issue: "
                            f"non-signal-safe '{match.group(1)}' call in handler '{h}'"
                        ),
                        severity="medium",
                        confidence=0.5,
                        file=context.file_path,
                        line=span_line,
                    )
                )

        return findings


def _find_function_body(content: str, name: str) -> tuple[int | None, int | None, int]:
    """Return (start_of_body, end_of_body, definition_line) for named function."""
    func_re = re.compile(
        rf"(?:^|[\n;}}])\s*(?:static\s+|extern\s+|inline\s+)*"
        rf"(?:[\w*:\s<>]+)\s+{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{",
        re.MULTILINE,
    )
    m = func_re.search(content)
    if not m:
        return None, None, 0
    start = m.end() - 1  # the '{'
    depth = 1
    j = start + 1
    while j < len(content):
        if content[j] == "{":
            depth += 1
        elif content[j] == "}":
            depth -= 1
            if depth == 0:
                return start, j + 1, _offset_to_line(content, m.start())
        j += 1
    return start, len(content), _offset_to_line(content, m.start())


def _offset_to_line(content: str, offset: int) -> int:
    return content.count("\n", 0, min(offset, len(content))) + 1
