"""Unit tests for the ValidationEngine routing and verdict merging."""

from __future__ import annotations

from pathlib import Path

from vra.core.enums import Severity, ValidationResult
from vra.core.models import Finding, SourceLocation
from vra.rules.validation import build_validation_engine
from vra.rules.validation.base import ValidationEngine


def _finding(category: str, cwe: str, line: int = 2) -> Finding:
    return Finding(
        id="F-00004",
        title="candidate",
        category=category,
        cwe=cwe,
        severity=Severity.MEDIUM,
        confidence=0.7,
        source=SourceLocation(file="src/demo.c", line=line, function="f"),
    )


def test_engine_demotes_fp_when_validator_applies():
    content = (
        "void f() {\n"
        "  char *p = (char *)malloc(64);\n"
        "  free(p);\n"
        "}\n"
    )
    engine = build_validation_engine()
    finding = _finding("resource-management", "CWE-401")
    out = engine.validate(finding, content, Path("/proj"))
    assert out.verdict is ValidationResult.LIKELY_FP
    assert out.indicators


def test_engine_confirms_when_validator_applies():
    content = "void f() { char *p = (char *)malloc(64); }\n"
    engine = build_validation_engine()
    finding = _finding("resource-management", "CWE-401", line=1)
    out = engine.validate(finding, content, Path("/proj"))
    assert out.verdict is ValidationResult.CONFIRMED


def test_engine_leaves_unknown_categories_suspicious():
    engine = build_validation_engine()
    finding = _finding("miscellaneous", "CWE-999", line=1)
    out = engine.validate(finding, "x", Path("/proj"))
    assert out.verdict is ValidationResult.SUSPICIOUS
    assert not out.indicators


def test_empty_engine_is_suspicious():
    finding = _finding("resource-management", "CWE-401", line=1)
    out = ValidationEngine().validate(finding, "x", Path("/proj"))
    assert out.verdict is ValidationResult.SUSPICIOUS
