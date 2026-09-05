"""Unit tests for the high-volume validators (CWE-134/252/338/674/20)."""

from __future__ import annotations

from pathlib import Path

from vra.core.enums import ControllabilityLevel, Severity, ValidationResult
from vra.core.models import DataFlowStep, Finding, SourceLocation
from vra.rules.validation.format_string import FormatStringValidator
from vra.rules.validation.input_validation import InputValidationValidator
from vra.rules.validation.recursion import RecursionValidator
from vra.rules.validation.resource_result import ResourceResultValidator
from vra.rules.validation.weak_random import WeakRandomValidator


def _finding(
    line: int,
    cwe: str,
    *,
    tag: str | None = None,
    snippet: str = "",
) -> Finding:
    flow = []
    if tag:
        flow = [
            DataFlowStep(
                variable="v",
                location=SourceLocation(file="src/v.c", line=1, function="f"),
                description=f"input -> sink ({tag})",
            )
        ]
    return Finding(
        id="F-HV",
        title="candidate",
        category="input",
        cwe=cwe,
        severity=Severity.MEDIUM,
        confidence=0.5,
        source=SourceLocation(file="src/v.c", line=line, function="f"),
        source_snippet=snippet,
        dataflow=flow,
        controllability=ControllabilityLevel.HIGH,
    )


# ---------------------------------------------------------------------------
# FormatStringValidator (CWE-134)
# ---------------------------------------------------------------------------

def test_format_string_constant_macro_is_fp():
    content = "void f() {\n  int x = 1;\n  printf(FMT_STR, x);\n}\n"
    out = FormatStringValidator().validate(_finding(3, "CWE-134"), content, Path("/p"))
    assert out.verdict is ValidationResult.LIKELY_FP


def test_format_string_attacker_root_is_confirmed():
    content = "void f() {\n  printf(buf, 1);\n}\n"
    out = FormatStringValidator().validate(_finding(2, "CWE-134", tag="network"), content, Path("/p"))
    assert out.verdict is ValidationResult.CONFIRMED


def test_format_string_no_provenance_is_suspicious():
    content = "void f() {\n  printf(fmt, 1);\n}\n"
    out = FormatStringValidator().validate(_finding(2, "CWE-134"), content, Path("/p"))
    assert out.verdict is ValidationResult.SUSPICIOUS


def test_format_string_no_provenance_is_fp_in_strict():
    content = "void f() {\n  printf(fmt, 1);\n}\n"
    out = FormatStringValidator(strict=True).validate(_finding(2, "CWE-134"), content, Path("/p"))
    assert out.verdict is ValidationResult.LIKELY_FP


# ---------------------------------------------------------------------------
# ResourceResultValidator (CWE-252)
# ---------------------------------------------------------------------------

def test_unchecked_open_result_consumed_next_line_is_fp():
    content = (
        "void f() {\n"
        "  int fd = 0;\n"
        "  open(\"cfg\", O_RDONLY);\n"
        "  if (fd == -1) return;\n"
        "}\n"
    )
    out = ResourceResultValidator().validate(_finding(3, "CWE-252"), content, Path("/p"))
    assert out.verdict is ValidationResult.LIKELY_FP


def test_unchecked_priv_call_is_confirmed():
    content = "void f() {\n  setuid(0);\n}\n"
    out = ResourceResultValidator().validate(_finding(2, "CWE-252"), content, Path("/p"))
    assert out.verdict is ValidationResult.CONFIRMED


def test_unchecked_read_probe_is_fp():
    content = "void f(int fd, char *b, size_t n) {\n  read(fd, b, n);\n}\n"
    out = ResourceResultValidator().validate(_finding(2, "CWE-252"), content, Path("/p"))
    assert out.verdict is ValidationResult.LIKELY_FP


# ---------------------------------------------------------------------------
# WeakRandomValidator (CWE-338)
# ---------------------------------------------------------------------------

def test_rand_without_security_context_is_fp():
    content = "void f() {\n  int x = rand();\n  use(x);\n}\n"
    out = WeakRandomValidator().validate(_finding(2, "CWE-338"), content, Path("/p"))
    assert out.verdict is ValidationResult.LIKELY_FP


def test_rand_near_secret_material_is_suspicious():
    content = (
        "void make_token() {\n"
        "  init();\n"
        "  int x = rand();\n"
        "  mix(salt, x);\n"
        "}\n"
    )
    out = WeakRandomValidator().validate(_finding(3, "CWE-338"), content, Path("/p"))
    assert out.verdict is ValidationResult.SUSPICIOUS


# ---------------------------------------------------------------------------
# RecursionValidator (CWE-674)
# ---------------------------------------------------------------------------

def test_depth_guarded_recursion_is_fp():
    content = (
        "void walk(node *n, int depth) {\n"
        "  if (depth == 0) return;\n"
        "  walk(n->next, depth - 1);\n"
        "}\n"
    )
    out = RecursionValidator().validate(_finding(1, "CWE-674"), content, Path("/p"))
    assert out.verdict is ValidationResult.LIKELY_FP


def test_unguarded_recursion_is_suspicious():
    content = (
        "void walk(node *n, int depth) {\n"
        "  walk(n->next, depth + 1);\n"
        "}\n"
    )
    out = RecursionValidator().validate(_finding(1, "CWE-674"), content, Path("/p"))
    assert out.verdict is ValidationResult.SUSPICIOUS


# ---------------------------------------------------------------------------
# InputValidationValidator (CWE-20)
# ---------------------------------------------------------------------------

def test_env_value_length_checked_into_bounded_sink_is_fp():
    content = (
        "void f() {\n"
        "  const char *v = getenv(\"X\");\n"
        "  if (n < 32) return;\n"
        "  memcpy(dst, v, n);\n"
        "}\n"
    )
    out = InputValidationValidator().validate(_finding(2, "CWE-20"), content, Path("/p"))
    assert out.verdict is ValidationResult.LIKELY_FP


def test_env_value_without_bounded_sink_is_suspicious():
    content = (
        "void f() {\n"
        "  const char *v = getenv(\"X\");\n"
        "  strcpy(dst, v);\n"
        "}\n"
    )
    out = InputValidationValidator().validate(_finding(2, "CWE-20"), content, Path("/p"))
    assert out.verdict is ValidationResult.SUSPICIOUS


def test_env_value_ambient_only_is_fp():
    content = "void f() {\n  const char *v = getenv(\"X\");\n  use(v);\n}\n"
    out = InputValidationValidator().validate(_finding(2, "CWE-20", tag="cli"), content, Path("/p"))
    assert out.verdict is ValidationResult.LIKELY_FP
