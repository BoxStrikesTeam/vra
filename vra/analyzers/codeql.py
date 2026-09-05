"""CodeQL analyzer adapter for VRA."""

from __future__ import annotations

import json
import time

from vra.analyzers.base import Analyzer, AnalyzerCapabilities
from vra.analyzers.registry import AnalyzerRegistry
from vra.core.enums import RunStatus
from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding, ToolRunResult

log = get_logger("analyzers.codeql")


@AnalyzerRegistry.register
class CodeQLAnalyzer(Analyzer):
    name = "codeql"
    version = "1.0.0"
    capabilities = AnalyzerCapabilities(requires_build=True)

    def prepare(self, context: AnalysisContext) -> None:
        pass

    def run(self, context: AnalysisContext) -> ToolRunResult:
        if not self.available():
            return ToolRunResult(
                analyzer_name=self.name,
                status=RunStatus.SKIPPED,
                error_message="codeql not found",
            )

        db_path = context.workspace_dir / "codeql-db"
        source_dir = str(context.project.path)

        start = time.monotonic()

        create_cmd = [
            "codeql",
            "database",
            "create",
            str(db_path),
            "--language=cpp",
            f"--source-root={source_dir}",
        ]
        stdout, stderr, rc = self._execute_tool(create_cmd, timeout=600)
        if rc != 0:
            return ToolRunResult(
                analyzer_name=self.name,
                status=RunStatus.FAILED,
                error_message=f"CodeQL database creation failed: {stderr}",
                duration=time.monotonic() - start,
            )

        analyze_cmd = [
            "codeql",
            "database",
            "analyze",
            str(db_path),
            "--format=sarif-latest",
            "--ram=4096",
        ]
        stdout, stderr, rc = self._execute_tool(analyze_cmd, timeout=900)
        duration = time.monotonic() - start

        findings = []
        if stdout:
            try:
                findings = self.parse(stdout)
                findings = self.normalize(findings)
            except Exception as e:
                log.warning("Failed to parse CodeQL output: %s", e)

        return ToolRunResult(
            analyzer_name=self.name,
            raw_output=stdout,
            findings=findings,
            exit_code=rc,
            duration=duration,
            status=RunStatus.COMPLETED if rc >= 0 else RunStatus.FAILED,
        )

    def parse(self, raw_result: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(raw_result)
            for run in data.get("runs", []):
                for result in run.get("results", []):
                    rule_id = result.get("ruleId", "")
                    message = result.get("message", {}).get("text", "")
                    locations = result.get("locations", [])
                    if locations:
                        loc = locations[0].get("physicalLocation", {})
                        artifact = loc.get("artifactLocation", {})
                        region = loc.get("region", {})
                        findings.append(
                            self._make_finding(
                                title=f"{rule_id}: {message}"[:200],
                                category="codeql",
                                cwe=self._map_rule_to_cwe(rule_id),
                                severity="medium",
                                confidence=0.8,
                                file=artifact.get("uri", ""),
                                line=region.get("startLine", 0),
                            )
                        )
        except (json.JSONDecodeError, KeyError) as e:
            log.debug("Parse error: %s", e)
        return findings

    def _map_rule_to_cwe(self, rule_id: str) -> str:
        mapping = {
            "cpp/unsafe-strncat": "CWE-120",
            "cpp/overflowing-snprintf": "CWE-120",
            "cpp/overflow-buffer": "CWE-119",
            "cpp/use-of-pointer-arithmetic": "CWE-823",
            "cpp/missing-check": "CWE-476",
        }
        return mapping.get(rule_id, "CWE-0")
