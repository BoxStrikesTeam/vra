"""Unit tests for the structural memory-leak validator (CWE-401)."""

from __future__ import annotations

from pathlib import Path

from vra.core.enums import Severity, ValidationResult
from vra.core.models import Finding, SourceLocation
from vra.rules.validation.memory_leak import MemoryLeakValidator


def _finding(line: int, snippet: str = "") -> Finding:
    return Finding(
        id="F-00001",
        title="Memory leak",
        category="resource-management",
        cwe="CWE-401",
        severity=Severity.MEDIUM,
        confidence=0.7,
        source=SourceLocation(file="src/leak.c", line=line, function="process"),
        source_snippet=snippet,
    )


def _validate(finding: Finding, content: str) -> ValidationResult:
    engine = MemoryLeakValidator()
    out = engine.validate(finding, content, Path("/proj"))
    return out.verdict


def test_leak_without_free_anywhere_is_confirmed():
    content = (
        "void process() {\n"
        "  char *p = (char *)malloc(64);\n"
        "  use(p);\n"
        "}\n"
    )
    assert _validate(_finding(2), content) is ValidationResult.CONFIRMED


def test_leak_with_matching_free_is_likely_fp():
    content = (
        "void process() {\n"
        "  char *p = (char *)malloc(64);\n"
        "  use(p);\n"
        "  free(p);\n"
        "}\n"
    )
    assert _validate(_finding(2), content) is ValidationResult.LIKELY_FP


def test_leak_with_reassignment_is_suspicious():
    content = (
        "void process() {\n"
        "  char *p = (char *)malloc(64);\n"
        "  p = load_global();\n"
        "}\n"
    )
    assert _validate(_finding(2), content) is ValidationResult.SUSPICIOUS
