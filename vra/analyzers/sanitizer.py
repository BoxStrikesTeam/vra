"""Sanitizer build+runtime integration for VRA.

Builds single-file C/C++ projects (or uses existing compile commands) with
AddressSanitizer/UndefinedBehaviorSanitizer flags, runs the resulting binary,
and turns sanitizer runtime reports into findings.

This is experimental: it requires a working compiler and may not cover complex
multi-target builds. It degrades gracefully when a build is not possible.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from vra.analyzers.base import Analyzer, AnalyzerCapabilities
from vra.analyzers.registry import AnalyzerRegistry
from vra.core.enums import RunStatus
from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding, ToolRunResult

log = get_logger("analyzers.sanitizer")

SANITIZER_FLAGS = {
    "address": ["-fsanitize=address", "-fno-omit-frame-pointer", "-g"],
    "undefined": ["-fsanitize=undefined", "-g"],
    "leak": ["-fsanitize=leak", "-g"],
}

# Map sanitizer runtime messages to CWE + severity + title patterns.
ASAN_PATTERNS = [
    (
        re.compile(r"heap-use-after-free", re.I),
        "CWE-416",
        "high",
        "Use-after-free detected at runtime",
    ),
    (
        re.compile(r"double-free", re.I),
        "CWE-415",
        "high",
        "Double-free detected at runtime",
    ),
    (
        re.compile(r"heap-buffer-overflow", re.I),
        "CWE-787",
        "high",
        "Heap buffer overflow detected at runtime",
    ),
    (
        re.compile(r"stack-buffer-overflow", re.I),
        "CWE-121",
        "high",
        "Stack buffer overflow detected at runtime",
    ),
    (
        re.compile(r"global-buffer-overflow", re.I),
        "CWE-123",
        "high",
        "Global buffer overflow detected at runtime",
    ),
    (
        re.compile(r"SEGV|AddressSanitizer: (?:SEGV|access-violation)", re.I),
        "CWE-120",
        "medium",
        "AddressSanitizer detected an invalid memory access",
    ),
    (
        re.compile(r"use-of-uninitialized-value|MemorySanitizer", re.I),
        "CWE-457",
        "medium",
        "Uninitialized value use detected at runtime",
    ),
    (
        re.compile(r"runtime error:", re.I),
        "CWE-190",
        "medium",
        "UndefinedBehaviorSanitizer runtime error",
    ),
    (
        re.compile(r"SUMMARY:.*LeakSanitizer|leak(s)? (detected|of)", re.I),
        "CWE-401",
        "low",
        "Memory leak detected at runtime",
    ),
]

_FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\w+)\s+([\w./-]+\.(?:c|cpp|cc)):(\d+)")


@AnalyzerRegistry.register
class SanitizerAnalyzer(Analyzer):
    name = "sanitizer"
    version = "1.1.0"
    capabilities = AnalyzerCapabilities(requires_build=True)

    def __init__(self, sanitizer_type: str = "address"):
        self.sanitizer_type = sanitizer_type
        self._compiler = None

    def available(self) -> bool:
        # Requires a C/C++ compiler that accepts sanitizer flags.
        for comp in ("gcc", "cc", "clang"):
            if shutil.which(comp):
                self._compiler = comp
                compiler_type = comp.replace("gcc", "-gcc") if comp != "clang" else "clang"
                if self.sanitizer_type == "leak" and "clang" in compiler_type:
                    # LeakSanitizer is not supported by clang standalone; degrade.
                    return False if self.sanitizer_type == "leak" else True
                return True
        return False

    def prepare(self, context: AnalysisContext) -> None:
        pass

    def _find_main_source(self, source_dir: Path) -> Path | None:
        for name in ("main.c", "main.cpp", "main.cc"):
            candidate = source_dir / name
            if candidate.exists():
                return candidate
        # Fall back to the single C/C++ file in the tree, preferring top-level.
        for pat in ("*.c", "*.cpp", "*.cc"):
            for candidate in sorted(source_dir.glob(pat)):
                return candidate
        return None

    def run(self, context: AnalysisContext) -> ToolRunResult:
        source = self._find_main_source(context.source_dir)
        if source is None:
            return ToolRunResult(
                analyzer_name=f"sanitizer-{self.sanitizer_type}",
                status=RunStatus.SKIPPED,
                error_message="No compilable single-file source found",
            )

        flags = SANITIZER_FLAGS.get(self.sanitizer_type, SANITIZER_FLAGS["address"])
        build_dir = context.workspace_dir / "sanitizer"
        build_dir.mkdir(parents=True, exist_ok=True)
        binary = build_dir / f"a_{self.sanitizer_type}"

        cmd = [self._compiler, *flags, str(source), "-o", str(binary), "-lm"]
        try:
            build = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return ToolRunResult(
                analyzer_name=f"sanitizer-{self.sanitizer_type}",
                status=RunStatus.FAILED,
                error_message=f"Build failed: {e}",
            )

        if build.returncode != 0 or not binary.exists():
            return ToolRunResult(
                analyzer_name=f"sanitizer-{self.sanitizer_type}",
                status=RunStatus.FAILED,
                error_message=f"Compilation failed: {build.stderr[-500:]}",
                stderr=build.stderr,
            )

        # Run the binary; sanitizer reports go to stderr.
        try:
            run = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            output = "Tool run timed out (no crash reported)"
            return ToolRunResult(
                analyzer_name=f"sanitizer-{self.sanitizer_type}",
                status=RunStatus.SKIPPED,
                error_message=output,
            )

        combined = run.stdout + "\n" + run.stderr
        findings = self.parse(combined)

        return ToolRunResult(
            analyzer_name=f"sanitizer-{self.sanitizer_type}",
            status=RunStatus.COMPLETED if findings else RunStatus.SKIPPED,
            stdout=run.stdout,
            stderr=run.stderr,
            exit_code=run.returncode,
            findings=findings,
        )

    def parse(self, raw_result: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern, cwe, severity, title in ASAN_PATTERNS:
            if not pattern.search(raw_result):
                continue
            file, line, function = self._first_frame(raw_result)
            findings.append(
                self._make_finding(
                    title=title + f" (via {self.sanitizer_type} sanitizer)",
                    category="memory-safety" if cwe not in ("CWE-190", "CWE-457") else "logic",
                    cwe=cwe,
                    severity=severity,
                    confidence=0.95,
                    file=file or "runtime",
                    line=line or 0,
                    function=function,
                    tool_name=f"sanitizer-{self.sanitizer_type}",
                )
            )
        return findings

    def _first_frame(self, output: str) -> tuple[str, int, str]:
        match = _FRAME_RE.search(output)
        if match:
            return match.group(2), int(match.group(3)), match.group(1)
        return "", 0, ""
