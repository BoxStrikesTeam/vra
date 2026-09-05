"""Cppcheck analyzer adapter for VRA."""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET

from vra.analyzers.base import Analyzer, AnalyzerCapabilities
from vra.analyzers.registry import AnalyzerRegistry
from vra.core.enums import RunStatus
from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding, ToolRunResult

log = get_logger("analyzers.cppcheck")


@AnalyzerRegistry.register
class CppcheckAnalyzer(Analyzer):
    name = "cppcheck"
    version = "1.0.0"
    capabilities = AnalyzerCapabilities(source_only=True, requires_compile_commands=False)

    def prepare(self, context: AnalysisContext) -> None:
        pass

    def run(self, context: AnalysisContext) -> ToolRunResult:
        if not self.available():
            return ToolRunResult(
                analyzer_name=self.name,
                status=RunStatus.SKIPPED,
                error_message="cppcheck not found",
            )

        cmd = [
            "cppcheck",
            "--xml",
            "--xml-version=2",
            "--enable=warning,style,performance,portability",
            "--force",
            str(context.project.path),
        ]

        # On large projects --force is prohibitively slow; drop it.
        if context.project.total_files >= 1000:
            cmd = [c for c in cmd if c != "--force"]

        start = time.monotonic()
        stdout, stderr, return_code = self._execute_tool(cmd, timeout=self._timeout_for(context, 600))
        duration = time.monotonic() - start

        findings = []
        output = stderr if "error" in stderr.lower() or "<?xml" in stderr else stdout
        if output:
            try:
                findings = self.parse(output)
                findings = self.normalize(findings)
            except Exception as e:
                log.warning("Failed to parse cppcheck output: %s", e)

        return ToolRunResult(
            analyzer_name=self.name,
            raw_output=output,
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
            root = ET.fromstring(raw_result)
            for error in root.iter("error"):
                severity = error.get("severity", "information")
                msg = error.get("msg", "")
                error_id = error.get("id", "")
                location = error.find("location")
                file = ""
                line = 0
                func = ""
                if location is not None:
                    file = location.get("file", "")
                    line = int(location.get("line", 0))
                    func = location.get("function", "")

                sev_map = {
                    "error": "high",
                    "warning": "medium",
                    "style": "low",
                    "performance": "medium",
                    "portability": "low",
                    "information": "low",
                }
                sev = sev_map.get(severity.lower(), "medium")

                cwe = self._map_id_to_cwe(error_id)
                findings.append(
                    self._make_finding(
                        title=f"{error_id}: {msg}"[:200],
                        category="cppcheck",
                        cwe=cwe,
                        severity=sev,
                        confidence=0.6,
                        file=file,
                        line=line,
                        function=func,
                    )
                )
        except ET.ParseError as e:
            log.debug("XML parse error: %s", e)
        return findings

    def _map_id_to_cwe(self, error_id: str) -> str:
        mapping = {
            "memleak": "CWE-401",
            "resourceLeak": "CWE-404",
            "uninitvar": "CWE-457",
            "uninitMemberVar": "CWE-457",
            "bufferAccessOutOfBounds": "CWE-119",
            "possibleBufferAccessOutOfBounds": "CWE-119",
            "nullPointer": "CWE-476",
            "nullPointerRedundantCheck": "CWE-476",
            "doubleFree": "CWE-415",
            "uselessAssignmentArg": "CWE-563",
            "unusedFunction": "CWE-1164",
        }
        return mapping.get(error_id, "CWE-0")
