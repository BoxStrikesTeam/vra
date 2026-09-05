"""Path hijacking / untrusted search-path detection rules.

Covers vulnerabilities that arise when attacker-influenced data is used in a
way that changes the run-time environment the *operating system* looks at when
resolving a file or command path:

* CWE-426  Uncontrolled search path element (PATH hijacking).
* CWE-427  Uncontrolled search path element (PATH-relative command execution).
* CWE-22   Path traversal/relative path escapes fed to open/fopen/stat.

These are practical, line-oriented rules in the same spirit as the other VRA
rules: they flag *candidates* and report confidence rather than certainty.
"""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

# --- Untrusted search path: relying on $PATH for a command/exec --------------
# exec*/system/popen where the command name does not contain a slash "."
PATH_RELIANT_CALLS = re.compile(
    r"\b(execl|execlp|execle|execv|execvp|execve|system|popen|posix_spawnp)\s*\("
)
_LITERAL_RE = re.compile(r'(["\'])(?:[^"\'\\]|\\.|\\\\)*\1')

# --- PATH assignment / manipulation ------------------------------------------
PATH_ASSIGN = re.compile(
    r"(?:setenv|putenv|setlocalenv)\s*\(\s*[\"']?\s*PATH\b", re.I
)
PATH_GLOBAL_RE = re.compile(r"\bPATH\s*=")

# --- Path construction from user data ----------------------------------------
# A non-literal argument to the path-opening family.
OPEN_SINKS = re.compile(
    r"\b(open|openat|fopen|fopen_s|freopen|stat|lstat|fstatat|access|opendir)\s*\("
)
# Variables that plausibly carry user input.
USERLIKE = re.compile(
    r"\b(argv|argc|optarg|getenv|input|request|user|param|path|file|fname|"
    r"filename|name|dir|src|data|buf|buffer|ctx|msg)\b", re.I
)
# Explicit ".." traversal after concatenation.
TRAVERSAL_RE = re.compile(r"\.\.\s*[/\\]|\.\.\s*[\"']")


@RuleRegistry.register
class PathHijackingRule(SecurityRule):
    """Untrusted search path / PATH hijacking (CWE-426/427)."""

    name = "path-hijacking"
    category = "input"
    cwe = "CWE-426"
    description = "Detects untrusted search-path reliance and path hijacking"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.file_content.split("\n")
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            self._check_path_reliance(line, i, lines, findings, context)
            self._check_path_assignment(line, i, findings, context)
        return findings

    # -- (1) command run via PATH without a fully-qualified path --------------
    def _check_path_reliance(self, line: str, lineno: int, lines: list[str], findings, ctx) -> None:
        m = PATH_RELIANT_CALLS.search(line)
        if not m:
            return
        after = line[m.end() :]
        # Literal constant command -> not attacker-controlled path.
        if _LITERAL_RE.match(after.lstrip()):
            return
        # If an unqualified command name is executed and PATH could be hostile,
        # flag it as CWE-426 candidate.
        findings.append(
            self._make_finding(
                title=(
                    "Untrusted search path: command launched without a "
                    "fully-qualified path (PATH hijacking candidate)"
                ),
                severity="medium",
                confidence=0.4,
                file=ctx.file_path,
                line=lineno,
            )
        )

    # -- (2) PATH is mutated to include attacker-influenced directories --------
    def _check_path_assignment(self, line: str, lineno: int, findings, ctx) -> None:
        if not (PATH_ASSIGN.search(line) or PATH_GLOBAL_RE.search(line)):
            return
        # Only flag when the value is not a fixed constant string.
        rhs = line.split("=", 1)[-1].strip() if "=" in line else ""
        if not _LITERAL_RE.match(rhs):
            findings.append(
                self._make_finding(
                    title="Potential uncontrolled search path: PATH set/modified from runtime data",
                    severity="medium",
                    confidence=0.45,
                    file=ctx.file_path,
                    line=lineno,
                )
            )


@RuleRegistry.register
class PathTraversalRule(SecurityRule):
    """Path traversal passed to a file/stream opener (CWE-22)."""

    name = "path-traversal"
    category = "input"
    cwe = "CWE-22"
    description = "Detects attacker-controlled path concatenation to open/stat"

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.file_content.split("\n")
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if not OPEN_SINKS.search(line):
                continue
            # Never flag a literal constant path.
            if _LITERAL_RE.search(line) and not USERLIKE.search(line):
                continue
            if USERLIKE.search(line) or TRAVERSAL_RE.search(line):
                findings.append(
                    self._make_finding(
                        title="Potential path traversal: user-derived path passed to file/stream opener",
                        severity="high",
                        confidence=0.5 if TRAVERSAL_RE.search(line) else 0.4,
                        file=context.file_path,
                        line=i,
                    )
                )
        return findings
