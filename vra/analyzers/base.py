"""Analyzer base class and plugin system for VRA."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding, ToolRunResult

log = get_logger("analyzers")


@dataclass
class AnalyzerCapabilities:
    requires_build: bool = False
    requires_compile_commands: bool = False
    source_only: bool = False


class Analyzer(ABC):
    name: str = "base"
    version: str = "0.0.0"
    capabilities: AnalyzerCapabilities = field(default_factory=AnalyzerCapabilities)

    def available(self) -> bool:
        return shutil.which(self.name) is not None

    def get_version(self) -> str:
        return self.version

    @abstractmethod
    def prepare(self, context: AnalysisContext) -> None: ...

    @abstractmethod
    def run(self, context: AnalysisContext) -> ToolRunResult: ...

    @abstractmethod
    def parse(self, raw_result: str) -> list[Finding]: ...

    def normalize(self, parsed: list[Finding]) -> list[Finding]:
        return parsed

    def _execute_tool(self, cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
        import subprocess

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except FileNotFoundError:
            return "", f"Tool not found: {cmd[0]}", -1
        except subprocess.TimeoutExpired:
            return "", f"Tool timed out after {timeout}s", -2

    def _timeout_for(self, context, default: int) -> int:
        """Scale tool timeout down for very large projects to stay responsive."""
        total = 0
        try:
            total = context.project.total_files
        except AttributeError:
            return default
        if total >= 5000:
            return min(default, 180)
        if total >= 1000:
            return min(default, 300)
        return default

    def _make_finding(
        self,
        title: str,
        category: str,
        cwe: str,
        severity: str,
        confidence: float,
        file: str,
        line: int,
        function: str = "",
        tool_name: str = "",
    ) -> Finding:
        from vra.core.models import SourceLocation

        return Finding(
            id="",
            title=title,
            category=category,
            cwe=cwe,
            severity=severity,
            confidence=confidence,
            source=SourceLocation(file=file, line=line, function=function),
            tools=[tool_name or self.name],
        )
