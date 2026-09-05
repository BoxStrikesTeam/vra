"""Unit tests for the structural null-deref validator (CWE-476)."""

from __future__ import annotations

from pathlib import Path

from vra.core.enums import Severity, ValidationResult
from vra.core.models import Finding, SourceLocation
from vra.rules.validation.null_deref import NullDerefValidator


def _finding(line: int, snippet: str) -> Finding:
    return Finding(
        id="F-00002",
        title="Null pointer dereference",
        category="null-safety",
        cwe="CWE-476",
        severity=Severity.HIGH,
        confidence=0.8,
        source=SourceLocation(file="src/deref.c", line=line, function="run"),
        source_snippet=snippet,
    )


def _validate(finding: Finding, content: str) -> ValidationResult:
    out = NullDerefValidator().validate(finding, content, Path("/proj"))
    return out.verdict


def test_unchecked_deref_is_confirmed():
    content = (
        "void run() {\n"
        "  Node *n = fetch();\n"
        "  n->value = 1;\n"
        "}\n"
    )
    assert _validate(_finding(3, "n->value = 1;"), content) is ValidationResult.CONFIRMED


def test_guarded_deref_is_likely_fp():
    content = (
        "void run() {\n"
        "  Node *n = fetch();\n"
        "  if (!n) return;\n"
        "  n->value = 1;\n"
        "}\n"
    )
    assert _validate(_finding(4, "n->value = 1;"), content) is ValidationResult.LIKELY_FP


def test_null_equality_guard_is_likely_fp():
    content = (
        "void run() {\n"
        "  Node *n = fetch();\n"
        "  if (n == NULL) return;\n"
        "  n->value = 1;\n"
        "}\n"
    )
    assert _validate(_finding(4, "n->value = 1;"), content) is ValidationResult.LIKELY_FP
