"""Unit tests for the function locator and call graph builder."""

from __future__ import annotations

from pathlib import Path

import pytest

from vra.analysis.callgraph.builder import CallGraphBuilder
from vra.analysis.function_locator import clear_cache, find_function_at

SAMPLE_C = """\
#include <stdlib.h>

char *parse_attribute(const char *input, int input_len) {
    char *buffer = malloc(64);
    if (!buffer) return NULL;
    memcpy(buffer, input, input_len);
    return buffer;
}

int main(void) {
    char *ptr = malloc(32);
    free(ptr);
    return 0;
}
"""


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    p = tmp_path / "sample.c"
    p.write_text(SAMPLE_C)
    return p


def test_find_function_name_for_pointer_return_type(sample_file: Path):
    clear_cache()
    # memcpy sits inside parse_attribute (lines 4-6 map to the function body).
    names = {find_function_at(sample_file, ln) for ln in range(4, 9)}
    assert "parse_attribute" in names


def test_find_main_function(sample_file: Path):
    clear_cache()
    assert find_function_at(sample_file, 13) == "main"


def test_find_return_empty_outside_function(sample_file: Path):
    clear_cache()
    # Lines well past the last function return empty.
    result = {find_function_at(sample_file, ln) for ln in range(100, 110)}
    assert result == {""}


def test_call_graph_builds_functions(tmp_path: Path):
    p = tmp_path / "proj"
    p.mkdir()
    (p / "a.c").write_text("int helper(void) { return 1; }\nint main(void) { return helper(); }\n")
    graph = CallGraphBuilder(p).build()
    assert "main" in graph.functions
    assert "helper" in graph.functions
    assert graph.entry_points == ["main"]


def test_call_graph_no_path_when_not_called(tmp_path: Path):
    p = tmp_path / "proj"
    p.mkdir()
    (p / "a.c").write_text("int other(void) { return 1; }\nint main(void) { return 0; }\n")
    graph = CallGraphBuilder(p).build()
    assert graph.build_path("main", "other") is None
