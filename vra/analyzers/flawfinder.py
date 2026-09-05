"""Flawfinder analyzer adapter for VRA."""

from __future__ import annotations

import json
import time

from vra.analyzers.base import Analyzer, AnalyzerCapabilities
from vra.analyzers.registry import AnalyzerRegistry
from vra.core.enums import RunStatus
from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding, ToolRunResult

log = get_logger("analyzers.flawfinder")


@AnalyzerRegistry.register
class FlawfinderAnalyzer(Analyzer):
    name = "flawfinder"
    version = "1.0.0"
    capabilities = AnalyzerCapabilities(source_only=True)

    def prepare(self, context: AnalysisContext) -> None:
        pass

    def run(self, context: AnalysisContext) -> ToolRunResult:
        if not self.available():
            return ToolRunResult(
                analyzer_name=self.name,
                status=RunStatus.SKIPPED,
                error_message="flawfinder not found",
            )

        cmd = ["flawfinder", "--json", "--quiet", str(context.project.path)]

        start = time.monotonic()
        stdout, stderr, return_code = self._execute_tool(cmd, timeout=300)
        duration = time.monotonic() - start

        findings = []
        if stdout:
            try:
                findings = self.parse(stdout)
                findings = self.normalize(findings)
            except Exception as e:
                log.warning("Failed to parse flawfinder output: %s", e)

        return ToolRunResult(
            analyzer_name=self.name,
            raw_output=stdout,
            findings=findings,
            exit_code=return_code,
            duration=duration,
            status=RunStatus.COMPLETED if return_code >= 0 else RunStatus.FAILED,
        )

    def parse(self, raw_result: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(raw_result)
            if isinstance(data, list):
                for item in data:
                    findings.append(self._parse_item(item))
        except json.JSONDecodeError:
            pass
        return findings

    def _parse_item(self, item: dict) -> Finding:
        level = item.get("level", 0)
        sev_map = {0: "low", 1: "low", 2: "medium", 3: "medium", 4: "high", 5: "high"}
        return self._make_finding(
            title=f"{item.get('name', '')}: {item.get('context', '')}"[:200],
            category="flawfinder",
            cwe=item.get("cwe", "CWE-0"),
            severity=sev_map.get(level, "medium"),
            confidence=0.5,
            file=item.get("fname", ""),
            line=int(item.get("line", 0)),
        )
