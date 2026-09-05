"""Clang Static Analyzer adapter for VRA."""

from __future__ import annotations

import json
import time

from vra.analyzers.base import Analyzer, AnalyzerCapabilities
from vra.analyzers.registry import AnalyzerRegistry
from vra.core.enums import RunStatus
from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding, ToolRunResult

log = get_logger("analyzers.clang_analyzer")


@AnalyzerRegistry.register
class ClangAnalyzerAnalyzer(Analyzer):
    name = "clang"
    version = "1.0.0"
    capabilities = AnalyzerCapabilities(requires_compile_commands=False)

    def prepare(self, context: AnalysisContext) -> None:
        pass

    def run(self, context: AnalysisContext) -> ToolRunResult:
        if not self.available():
            return ToolRunResult(
                analyzer_name=self.name,
                status=RunStatus.SKIPPED,
                error_message="clang not found",
            )

        source_files = (
            list(context.project.path.rglob("*.c"))
            + list(context.project.path.rglob("*.cpp"))
            + list(context.project.path.rglob("*.cc"))
        )

        if not source_files:
            return ToolRunResult(analyzer_name=self.name, status=RunStatus.COMPLETED)

        all_findings: list[Finding] = []
        start = time.monotonic()

        for src in source_files[:50]:
            cmd = [
                "clang",
                "--analyze",
                "-Xanalyzer",
                "-analyzer-output=json",
                "-o",
                "/dev/null",
                str(src),
            ]
            stdout, stderr, rc = self._execute_tool(cmd, timeout=120)
            if stdout:
                try:
                    findings = self.parse(stdout)
                    all_findings.extend(self.normalize(findings))
                except Exception as e:
                    log.debug("Parse error for %s: %s", src, e)

        duration = time.monotonic() - start
        return ToolRunResult(
            analyzer_name=self.name,
            findings=all_findings,
            status=RunStatus.COMPLETED,
            duration=duration,
        )

    def parse(self, raw_result: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(raw_result)
            items = data if isinstance(data, list) else [data]
            for item in items:
                diag = item.get("diagnostics", item)
                if isinstance(diag, list):
                    for d in diag:
                        findings.append(self._parse_diagnostic(d))
                elif isinstance(diag, dict):
                    findings.append(self._parse_diagnostic(diag))
        except json.JSONDecodeError:
            pass
        return findings

    def _parse_diagnostic(self, diag: dict) -> Finding:
        path = diag.get("path", [])
        location = diag.get("location", {})
        file = location.get("file", "")
        line = location.get("line", 0)

        if path and isinstance(path, list):
            for step in path:
                if step.get("kind") == "call":
                    file = step.get("location", {}).get("file", file)
                    line = step.get("location", {}).get("line", line)

        return self._make_finding(
            title=diag.get("description", "Unknown issue")[:200],
            category="clang-analyzer",
            cwe="CWE-0",
            severity="medium",
            confidence=0.75,
            file=file,
            line=line,
        )
