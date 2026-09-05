"""Structural validation for command-injection findings (CWE-78).

FP-prone cases: fully literal commands (no interpolation), or commands invoked
through a vetted vector (exec* with an explicit argument array). We check for
interpolation of a tainted value into the command string and for safe exec*.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome

_LITERAL_COMMAND = re.compile(r'["\']$', re.MULTILINE)
_INTERPOLATION = re.compile(r"%(s|d|f|u|x|ld|p)|[+][^)]*[A-Za-z_]*\]|f?printf|vsprintf")
_SAFE_EXEC = re.compile(r"\b(execv|execvp|execve|execvpe|posix_spawn|fexecve)\s*\(")
_RAW_EXEC = re.compile(r"\b(system|popen|execl|execlp|execle)\s*\(")


class CommandInjectionValidator(SecurityValidator):
    name = "command-injection"
    categories = ("injection", "input", "process_exec", "command")
    cwes = ("CWE-78",)

    def validate(
        self, finding: Finding, source_content: str, source_dir: Path
    ) -> ValidationOutcome:
        snippet = finding.source_snippet or ""

        if _SAFE_EXEC.search(snippet):
            return ValidationOutcome(
                verdict=ValidationResult.LIKELY_FP,
                reason="Command invoked via exec* with an argument vector.",
                indicators=["uses exec* argument-array form, not a shell"],
            )

        if _RAW_EXEC.search(snippet) and not _INTERPOLATION.search(snippet):
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Shell call present, but no interpolation detected in snippet.",
            )

        if _INTERPOLATION.search(snippet) and _RAW_EXEC.search(snippet):
            return ValidationOutcome(
                verdict=ValidationResult.CONFIRMED,
                reason="Interpolated tainted data reaches a shell invocation.",
            )

        return ValidationOutcome(
            verdict=ValidationResult.SUSPICIOUS,
            reason="Command-execution call present; requires manual review.",
        )
