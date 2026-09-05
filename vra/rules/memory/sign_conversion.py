"""Unchecked signed/unsigned conversion detection rule (CWE-681)."""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

# Assignments/returns/casts that can convert a signed value to unsigned in a
# way that wraps a negative number large (e.g. used as a length/size).
SIGNED_VAR = re.compile(r"\b(int|long|short|ssize_t|off_t)\s+(\w+)\b")
UNSIGNED_TARGET = re.compile(r"\b(size_t|unsigned|uint(?:8|16|32|64)_t|size_t)\b")

# Dangerous cast like (size_t)neg or assignment to size_t from signed.
CAST_TO_UNSIGNED = re.compile(r"\(size_t\)\s*\w+|\(unsigned[^)]*\)\s*\w+")
SIZE_CONTEXT = re.compile(r"\b(memcpy|memmove|memset|strncpy|malloc|calloc|realloc|read|write|recv|send|snprintf)\s*\(")


@RuleRegistry.register
class SignConversionRule(SecurityRule):
    name = "sign-conversion"
    category = "memory"
    cwe = "CWE-681"
    description = "Detects unchecked signed to unsigned conversion in size contexts"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue

            # Direct cast of a signed value to unsigned.
            if CAST_TO_UNSIGNED.search(line) and SIGNED_VAR.search(line):
                findings.append(
                    self._make_finding(
                        title="Potential signed to unsigned conversion that may wrap negative values",
                        severity="medium",
                        confidence=0.45,
                        file=context.file_path,
                        line=i,
                    )
                )
                continue

            # A signed variable feeding a size in a memory operation.
            if SIZE_CONTEXT.search(line):
                for m in SIGNED_VAR.finditer(line):
                    if "unsigned" in line[: m.start()]:
                        continue
                    var = m.group(2)
                    if re.search(rf"\b{var}\b", SIZE_CONTEXT.search(line).group(0)):
                        findings.append(
                            self._make_finding(
                                title=f"Potential sign conversion: signed variable '{var}' used as a size",
                                severity="low",
                                confidence=0.4,
                                file=context.file_path,
                                line=i,
                            )
                        )
                        break
        return findings
