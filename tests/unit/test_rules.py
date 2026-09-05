"""Unit tests for custom rules."""

from pathlib import Path

from vra.core.models import ProjectInfo, RuleContext
from vra.rules.logic.null_deref import NullDerefRule
from vra.rules.memory.buffer_overflow import BufferOverflowRule
from vra.rules.memory.double_free import DoubleFreeRule
from vra.rules.memory.integer_overflow import IntegerOverflowRule
from vra.rules.memory.leak import MemoryLeakRule
from vra.rules.memory.use_after_free import UseAfterFreeRule


def _make_context(tmp_path: Path, content: str) -> RuleContext:
    src = Path(tmp_path) / "test.c"
    src.write_text(content)
    return RuleContext(
        project=ProjectInfo(),
        source_dir=tmp_path,
        file_path=str(src),
        file_content=content,
    )


def test_use_after_free_detects_uaf(tmp_path: Path):
    content = "void foo() {\n  char *p = malloc(16);\n  free(p);\n  p[0] = 'a';\n}\n"
    context = _make_context(tmp_path, content)
    findings = UseAfterFreeRule().analyze(context)
    assert len(findings) >= 1


def test_double_free_detects_df(tmp_path: Path):
    content = "void foo() {\n  char *p = malloc(16);\n  free(p);\n  free(p);\n}\n"
    context = _make_context(tmp_path, content)
    findings = DoubleFreeRule().analyze(context)
    assert len(findings) >= 1


def test_buffer_overflow_detects_unsafe(tmp_path: Path):
    content = "void foo() {\n  char buf[64];\n  memcpy(buf, src, len);\n}\n"
    context = _make_context(tmp_path, content)
    findings = BufferOverflowRule().analyze(context)
    assert len(findings) >= 1


def test_integer_overflow_detects_mul_alloc(tmp_path: Path):
    content = "void foo() {\n  size_t size = count * sizeof(int);\n  int *p = malloc(size);\n}\n"
    context = _make_context(tmp_path, content)
    findings = IntegerOverflowRule().analyze(context)
    assert len(findings) >= 1


def test_memory_leak_detects_alloc_no_free(tmp_path: Path):
    content = "void foo() {\n  char *p = malloc(16);\n  return;\n}\n"
    context = _make_context(tmp_path, content)
    findings = MemoryLeakRule().analyze(context)
    assert len(findings) >= 1


def test_null_deref_detects(tmp_path: Path):
    content = "void foo() {\n  char *p = malloc(16);\n  p[0] = 'a';\n}\n"
    context = _make_context(tmp_path, content)
    findings = NullDerefRule().analyze(context)
    assert len(findings) >= 1


def test_safe_code_no_false_positive(tmp_path: Path):
    content = """
#include <string.h>
void safe_copy(const char *src, size_t len) {
    char buf[64];
    if (len > sizeof(buf)) return;
    memcpy(buf, src, len);
}
"""
    context = _make_context(tmp_path, content)
    findings = BufferOverflowRule().analyze(context)
    for f in findings:
        assert f.confidence < 0.5
