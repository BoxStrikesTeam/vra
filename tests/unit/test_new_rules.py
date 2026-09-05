"""Unit tests for the newly added security rules."""

from __future__ import annotations

from vra.core.models import RuleContext
from vra.rules.input.command_injection import CommandInjectionRule
from vra.rules.input.format_string import FormatStringRule
from vra.rules.logic.race_condition import RaceConditionRule
from vra.rules.logic.stack_recursion import StackRecursionRule
from vra.rules.logic.toctou import ToctouRule
from vra.rules.memory.sign_conversion import SignConversionRule


def _ctx(code: str) -> RuleContext:
    return RuleContext(
        project="t",
        source_dir=".",
        file_path="test.c",
        file_content=code,
        compilation_db_path=None,
    )


def test_format_string_detects_user_controlled():
    res = FormatStringRule().analyze(_ctx("void g(char *u) { printf(u); }"))
    assert len(res) == 1
    assert res[0].cwe == "CWE-134"


def test_format_string_ignores_literal():
    res = FormatStringRule().analyze(_ctx('void g(void) { printf("%s\\n", x); }'))
    assert res == []


def test_command_injection_detects_variable_in_shell():
    res = CommandInjectionRule().analyze(_ctx('void g(char *u) { char b[100]; sprintf(b, "ls %s", u); system(b); }'))
    assert len(res) == 1
    assert res[0].cwe == "CWE-78"


def test_toctou_detects_check_then_use():
    code = """int f(const char *p) {
    if (access(p, W_OK) == 0) {
        int fd = open(p, O_RDWR);
        return fd;
    }
    return -1;
}
"""
    res = ToctouRule().analyze(_ctx(code))
    assert len(res) == 1
    assert res[0].cwe == "CWE-367"


def test_race_condition_detects_unsafe_call_in_handler():
    code = """static int c;
void handler(int sig) { c++; printf("caught\\n"); }
int main(void) { signal(SIGINT, handler); return 0; }
"""
    res = RaceConditionRule().analyze(_ctx(code))
    assert len(res) == 1
    assert res[0].cwe == "CWE-362"


def test_race_condition_ignores_no_handler():
    res = RaceConditionRule().analyze(_ctx("int main(void) { return 0; }"))
    assert res == []


def test_stack_recursion_detects_unbounded():
    res = StackRecursionRule().analyze(_ctx("int recurse(void) { return recurse(); }"))
    assert len(res) == 1
    assert res[0].cwe == "CWE-674"


def test_stack_recursion_ignores_guarded():
    res = StackRecursionRule().analyze(_ctx("int fact(int n) { if (n <= 1) return 1; return n * fact(n - 1); }"))
    assert res == []


def test_sign_conversion_detects_cast():
    res = SignConversionRule().analyze(_ctx("int f(void) { int x = -1; memcpy(dst, src, (size_t)x); }"))
    assert len(res) == 1
    assert res[0].cwe == "CWE-681"
