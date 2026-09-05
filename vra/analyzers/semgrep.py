"""Semgrep analyzer adapter for VRA."""

from __future__ import annotations

import json
import time

from vra.analyzers.base import Analyzer, AnalyzerCapabilities
from vra.analyzers.registry import AnalyzerRegistry
from vra.core.enums import RunStatus
from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding, ToolRunResult

log = get_logger("analyzers.semgrep")

SEMGREP_RULES = [
    "p/default",
    "p/owasp-top-ten",
    "p/cwe-top-25",
    "p/r2c-security-audit",
]


@AnalyzerRegistry.register
class SemgrepAnalyzer(Analyzer):
    name = "semgrep"
    version = "1.0.0"
    capabilities = AnalyzerCapabilities(source_only=True)

    def prepare(self, context: AnalysisContext) -> None:
        pass

    def run(self, context: AnalysisContext) -> ToolRunResult:
        if not self.available():
            return ToolRunResult(
                analyzer_name=self.name,
                status=RunStatus.SKIPPED,
                error_message="semgrep not found",
            )

        cmd = ["semgrep", "scan", "--json", "--quiet"]
        for rule in SEMGREP_RULES:
            cmd.extend(["--config", rule])
        cmd.append(str(context.project.path))

        start = time.monotonic()
        stdout, stderr, return_code = self._execute_tool(cmd, timeout=self._timeout_for(context, 600))
        duration = time.monotonic() - start

        findings = []
        if stdout:
            try:
                findings = self.parse(stdout)
                findings = self.normalize(findings)
            except Exception as e:
                log.warning("Failed to parse semgrep output: %s", e)

        return ToolRunResult(
            analyzer_name=self.name,
            raw_output=stdout,
            stdout=stdout,
            stderr=stderr,
            exit_code=return_code,
            duration=duration,
            findings=findings,
            status=RunStatus.COMPLETED if return_code >= 0 else RunStatus.FAILED,
        )

    def parse(self, raw_result: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(raw_result)
            for result in data.get("results", []):
                check_id = result.get("check_id", "")
                path = result.get("path", "")
                start_line = result.get("start", {}).get("line", 0)
                message = result.get("extra", {}).get("message", result.get("message", ""))
                severity = result.get("extra", {}).get("severity", result.get("severity", "WARNING"))
                metadata = result.get("extra", {}).get("metadata", {})
                cwe = metadata.get("cwe", ["CWE-0"])
                if isinstance(cwe, list) and cwe:
                    cwe = cwe[0]
                elif isinstance(cwe, list):
                    cwe = "CWE-0"

                sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
                sev = sev_map.get(str(severity).upper(), "medium")

                findings.append(
                    self._make_finding(
                        title=f"{check_id}: {message}"[:200],
                        category="semgrep",
                        cwe=cwe,
                        severity=sev,
                        confidence=0.7,
                        file=path,
                        line=start_line,
                    )
                )
        except (json.JSONDecodeError, KeyError) as e:
            log.debug("Parse error: %s", e)
        return findings
