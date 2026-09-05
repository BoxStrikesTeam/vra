"""Unit tests for the array-index validator (CWE-787 / CWE-125)."""

from __future__ import annotations

from pathlib import Path

from vra.core.enums import ControllabilityLevel, Severity, ValidationResult
from vra.core.models import DataFlowStep, Finding, SourceLocation
from vra.rules.validation.array_index import ArrayIndexValidator


def _finding(
    line: int,
    *,
    dataflow: bool,
    controllability: ControllabilityLevel,
    attacker_root: bool = False,
) -> Finding:
    flow = []
    if dataflow:
        desc = "attacker_len -> i (network)" if attacker_root else "len -> i"
        flow = [
            DataFlowStep(
                variable="i",
                location=SourceLocation(file="src/idx.c", line=1, function="f"),
                description=desc,
            )
        ]
    return Finding(
        id="F-00003",
        title="Array index out of bounds",
        category="taint",
        cwe="CWE-787",
        severity=Severity.MEDIUM,
        confidence=0.6,
        source=SourceLocation(file="src/idx.c", line=line, function="f"),
        dataflow=flow,
        controllability=controllability,
    )


def test_tainted_index_without_attacker_root_is_suspicious():
    content = "void f() { buf[i] = 1; }\n"
    f = _finding(1, dataflow=True, controllability=ControllabilityLevel.HIGH)
    out = ArrayIndexValidator().validate(f, content, Path("/proj"))
    assert out.verdict is ValidationResult.SUSPICIOUS


def test_attacker_root_index_without_bounds_is_confirmed():
    content = "void f() { buf[i] = 1; }\n"
    f = _finding(
        1,
        dataflow=True,
        controllability=ControllabilityLevel.HIGH,
        attacker_root=True,
    )
    out = ArrayIndexValidator().validate(f, content, Path("/proj"))
    assert out.verdict is ValidationResult.CONFIRMED


def test_untainted_index_is_likely_fp():
    content = "void f() { buf[i] = 1; }\n"
    f = _finding(1, dataflow=False, controllability=ControllabilityLevel.LOW)
    out = ArrayIndexValidator().validate(f, content, Path("/proj"))
    assert out.verdict is ValidationResult.LIKELY_FP


def test_tainted_index_with_bounds_check_is_suspicious():
    content = "void f() { if (i < N) { buf[i] = 1; } }\n"
    f = _finding(1, dataflow=True, controllability=ControllabilityLevel.HIGH)
    out = ArrayIndexValidator().validate(f, content, Path("/proj"))
    assert out.verdict is ValidationResult.SUSPICIOUS


def test_strict_mode_demotes_taint_without_attacker_root():
    content = "void f() { buf[i] = 1; }\n"
    f = _finding(1, dataflow=True, controllability=ControllabilityLevel.HIGH)
    out = ArrayIndexValidator(strict=True).validate(f, content, Path("/proj"))
    assert out.verdict is ValidationResult.LIKELY_FP
