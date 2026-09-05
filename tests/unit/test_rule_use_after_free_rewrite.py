"""Unit tests for the rebuilt use-after-free rule (CWE-416).

The rule now emits at most one finding per (pointer, free-site) at the first
genuine dereference and ignores guards, bare mentions and recovered pointers.
"""

from __future__ import annotations

from pathlib import Path

from vra.core.models import ProjectInfo, RuleContext
from vra.rules.memory.use_after_free import UseAfterFreeRule


def _find(contents: str) -> list:
    src = Path("/tmp/uaf_test.c")
    src.write_text(contents)
    ctx = RuleContext(
        project=ProjectInfo(),
        source_dir=Path("/tmp"),
        file_path=str(src),
        file_content=contents,
    )
    return UseAfterFreeRule().analyze(ctx)


def test_free_then_null_check_is_not_a_finding():
    code = "void f() {\n  char *p = malloc(16);\n  free(p);\n  if (p) { foo(); }\n}\n"
    assert _find(code) == []


def test_free_then_pointer_null_compare_is_not_a_finding():
    code = "void f() {\n  char *p = malloc(16);\n  free(p);\n  if (p == NULL) return;\n}\n"
    assert _find(code) == []


def test_free_then_deref_is_a_single_finding():
    code = "void f() {\n  char *p = malloc(16);\n  free(p);\n  p[0] = 'a';\n  puts(p);\n}\n"
    findings = _find(code)
    assert len(findings) == 1
    assert findings[0].source.line == 4


def test_free_then_call_argument_is_a_finding():
    code = "void f() {\n  char *p = malloc(16);\n  free(p);\n  strcpy(p, \"x\");\n}\n"
    findings = _find(code)
    assert len(findings) == 1
    assert findings[0].source.line == 4


def test_free_then_reassign_recovery_is_not_a_finding():
    code = "void f() {\n  char *p = malloc(16);\n  free(p);\n  p = NULL;\n  p[0] = 'a';\n}\n"
    assert _find(code) == []


def test_comment_mention_after_free_is_not_a_finding():
    code = "void f() {\n  char *p = malloc(16);\n  free(p);\n  /* p is stale */\n  foo();\n}\n"
    assert _find(code) == []
