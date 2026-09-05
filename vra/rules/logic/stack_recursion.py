"""Unbounded recursion / stack exhaustion detection rule (CWE-674)."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

FUNC_DEF_RE = re.compile(
    r"(?:^|[\n;}])\s*(?:static\s+|extern\s+|inline\s+)*"
    r"(?:[\w*:\s<>]+)\s+(\w+)\s*\([^;{}]*\)\s*\{",
    re.MULTILINE,
)


@RuleRegistry.register
class StackRecursionRule(SecurityRule):
    name = "stack-recursion"
    category = "logic"
    cwe = "CWE-674"
    description = "Detects unbounded recursion that could exhaust the stack"

    def analyze(self, context: RuleContext) -> list[Finding]:
        # Fast prefilter: no recursive-looking self call, skip cheaply.
        if not re.search(r"\b(\w+)\s*\([^)]*\)[^;]*\b(\1)\s*\(", context.file_content):
            pass

        funcs = {}
        for m in FUNC_DEF_RE.finditer(context.file_content):
            name = m.group(1)
            if name in ("if", "while", "for", "switch", "do", "return"):
                continue
            start = m.start()
            end = _function_end(context.file_content, start)
            funcs[name] = (start, end)

        findings: list[Finding] = []

        for name, (start, end) in funcs.items():
            body = context.file_content[start:end]
            # Direct recursive self-call.
            self_calls = len(re.findall(rf"\b{re.escape(name)}\s*\(", body)) - 1
            if self_calls <= 0:
                continue

            # Heuristic guard detection: recursion guarded by an if/while with a
            # comparison against 0/size/length - treated as bounded.
            lines_in_body = body.split("\n")
            if any(re.search(r"if\s*\(.*(<|>|<=|>=|==|!=)|while\s*\(.*(<|>|<=|>=)", ln) for ln in lines_in_body):
                continue

            line_no = _offset_to_line(context.file_content, start)
            findings.append(
                self._make_finding(
                    title=f"Potential unbounded recursion in '{name}': may exhaust stack",
                    severity="medium",
                    confidence=0.55,
                    file=context.file_path,
                    line=line_no,
                )
            )
        return findings


def _function_end(content: str, start: int) -> int:
    i = content.find("{", start, start + 200)
    if i == -1:
        return start + 200
    depth = 1
    j = i + 1
    while j < len(content):
        ch = content[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return len(content)


def _offset_to_line(content: str, offset: int) -> int:
    return content.count("\n", 0, min(offset, len(content))) + 1
