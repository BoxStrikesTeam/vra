"""Tests for the path hijacking / traversal rules."""

from __future__ import annotations

from pathlib import Path

from vra.core.models import ProjectInfo, RuleContext
from vra.rules.input.path_hijack import PathHijackingRule, PathTraversalRule


def _ctx(code: str, path: str = "/tmp/x.c") -> RuleContext:
    return RuleContext(
        project=ProjectInfo(path=Path("/tmp"), name="t"),
        source_dir=Path("/tmp"),
        file_path=path,
        file_content=code,
    )


def _lines(findings):
    return sorted({f.source.line for f in findings})


def test_unqualified_system_is_flagged():
    code = 'void f(char *user) { system(user); }\n'
    findings = PathHijackingRule().analyze(_ctx(code))
    assert findings, "expected a path-hijack finding"
    assert all(f.cwe == "CWE-426" for f in findings)


def test_qualified_and_literal_system_skipped():
    code = (
        'void f(void) { system("/usr/bin/ls"); system("ls"); }\n'
    )
    findings = PathHijackingRule().analyze(_ctx(code))
    assert not findings, "literal/qualified commands must not be flagged"


def test_path_env_modification_flagged():
    code = 'void f(char *d) { char b[128]; snprintf(b,48,"%s/bin",d); setenv("PATH",b,1); }\n'
    findings = PathHijackingRule().analyze(_ctx(code))
    assert findings
    assert {f.cwe for f in findings} == {"CWE-426"}


def test_traversal_concat_flagged():
    code = (
        "int f(char *fname) {\n"
        "    char path[256];\n"
        "    snprintf(path, 256, \"/data/%s\", fname);\n"
        "    return open(path, 0);\n"
        "}\n"
    )
    findings = PathTraversalRule().analyze(_ctx(code))
    assert findings
    assert all(f.cwe == "CWE-22" for f in findings)


def test_literal_open_skipped():
    code = '#include <fcntl.h>\nint f(void) { return open("/etc/hostname", 0); }\n'
    findings = PathTraversalRule().analyze(_ctx(code))
    assert not findings, "constant path open must not be flagged"
