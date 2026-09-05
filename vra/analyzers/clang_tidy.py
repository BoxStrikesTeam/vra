"""Clang-tidy analyzer adapter for VRA."""

from __future__ import annotations

import json
import re

from vra.analyzers.base import Analyzer, AnalyzerCapabilities
from vra.analyzers.registry import AnalyzerRegistry
from vra.core.enums import RunStatus
from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding, ToolRunResult

log = get_logger("analyzers.clang_tidy")

CLANG_TIDY_CHECKS = [
    "bugprone-*",
    "cert-*",
    "misc-*",
    "modernize-*",
    "performance-*",
    "clang-analyzer-*",
]


@AnalyzerRegistry.register
class ClangTidyAnalyzer(Analyzer):
    name = "clang-tidy"
    version = "1.0.0"
    capabilities = AnalyzerCapabilities(requires_compile_commands=True)

    def prepare(self, context: AnalysisContext) -> None:
        pass

    def run(self, context: AnalysisContext) -> ToolRunResult:
        import time

        if not self.available():
            return ToolRunResult(
                analyzer_name=self.name,
                status=RunStatus.SKIPPED,
                error_message="clang-tidy not found",
            )

        source_files = (
            list(context.project.path.rglob("*.c"))
            + list(context.project.path.rglob("*.cpp"))
            + list(context.project.path.rglob("*.cc"))
        )

        if not source_files:
            return ToolRunResult(analyzer_name=self.name, status=RunStatus.COMPLETED, findings=[])

        cmd = ["clang-tidy", "--dump-json"]
        for check in CLANG_TIDY_CHECKS:
            cmd.extend(["--checks", f"-*,{check}"])

        if context.build_result and context.build_result.compile_commands_path:
            cmd.extend(["-p", str(context.build_result.build_dir or context.project.path)])

        cmd.extend([str(f) for f in source_files[:100]])

        start = time.monotonic()
        stdout, stderr, return_code = self._execute_tool(cmd, timeout=600)
        duration = time.monotonic() - start

        findings = []
        if return_code == 0 or stdout:
            try:
                findings = self.parse(stdout)
                findings = self.normalize(findings)
            except Exception as e:
                log.warning("Failed to parse clang-tidy output: %s", e)

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
            diagnostics = (
                data.get("diagnostics", []) if isinstance(data, dict) else data if isinstance(data, list) else []
            )
            for diag in diagnostics:
                if diag.get("DiagnosticType") == "warning" or diag.get("level") == "warning":
                    loc = diag.get("DiagnosticLocation", diag.get("location", {}))
                    file = loc.get("File", loc.get("file", ""))
                    line = loc.get("FileLine", loc.get("line", 0))
                    func = loc.get("FunctionName", loc.get("function", ""))
                    message = diag.get("DiagnosticMessage", diag.get("message", ""))

                    cwe = self._map_check_to_cwe(diag.get("DiagnosticName", diag.get("check", "")))
                    findings.append(
                        self._make_finding(
                            title=message[:200],
                            category="clang-tidy",
                            cwe=cwe,
                            severity="medium",
                            confidence=0.7,
                            file=file,
                            line=line,
                            function=func,
                        )
                    )
        except json.JSONDecodeError:
            findings = self._parse_text_output(raw_result)
        return findings

    def _parse_text_output(self, output: str) -> list[Finding]:
        findings = []
        pattern = re.compile(r"^(.+?):(\d+):(\d+):\s+warning:\s+(.+?)\s+\[(.+?)\]", re.MULTILINE)
        for match in pattern.finditer(output):
            file, line, _col, message, check = match.groups()
            cwe = self._map_check_to_cwe(check)
            findings.append(
                self._make_finding(
                    title=message[:200],
                    category="clang-tidy",
                    cwe=cwe,
                    severity="medium",
                    confidence=0.7,
                    file=file,
                    line=int(line),
                )
            )
        return findings

    def _map_check_to_cwe(self, check: str) -> str:
        mapping = {
            "bugprone-sizeof-expression": "CWE-131",
            "bugprone-suspicious-string-compare": "CWE-697",
            "bugprone-unsafe-functions": "CWE-242",
            "cert-err33-c": "CWE-252",
            "misc-redundant-expression": "CWE-1164",
            "modernize-use-nullptr": "CWE-476",
            "performance-unnecessary-copy": "CWE-398",
        }
        return mapping.get(check, "CWE-0")
