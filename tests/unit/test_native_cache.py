"""Unit tests for the native file-level function range cache."""

from __future__ import annotations

from pathlib import Path

import pytest

from vra import _native as c

pytestmark = pytest.mark.skipif(
    not hasattr(c, "clear_caches"), reason="native extension not available"
)

SAMPLE = """\
#include <stdio.h>

int helper(void) {
    return 1;
}

void foo(int x) {
    printf("%d", x);
}

int bar(char *s) {
    return s ? 1 : 0;
}

int main(void) {
    helper();
    foo(3);
    bar("x");
    return 0;
}
"""


def _write_sample(tmp_path: Path) -> Path:
    src = tmp_path / "sample.c"
    src.write_text(SAMPLE)
    return src


def test_find_enclosing_function(tmp_path: Path):
    src = _write_sample(tmp_path)
    c.clear_caches()

    # SAMPLE line map (1-indexed):
    # helper body: 3-5 ; foo body: 7-9 ; bar body: 11-13 ; main body: 15-20
    assert c.find_function_at(str(src), 4) == "helper"
    assert c.find_function_at(str(src), 8) == "foo"
    assert c.find_function_at(str(src), 12) == "bar"
    assert c.find_function_at(str(src), 17) == "main"
    # Header / between functions -> empty
    assert c.find_function_at(str(src), 1) == ""
    assert c.find_function_at(str(src), 6) == ""


def test_cache_reuses_file(tmp_path: Path):
    src = _write_sample(tmp_path)
    c.clear_caches()

    # Warm the cache
    assert c.find_function_at(str(src), 4) == "helper"
    # Second call must still resolve correctly without re-parse
    assert c.find_function_at(str(src), 7) == "foo"
    assert c.find_function_at(str(src), 19) == "main"


def test_clear_cache_reset(tmp_path: Path):
    src = _write_sample(tmp_path)
    c.clear_caches()
    assert c.find_function_at(str(src), 8) == "foo"
    c.clear_caches()
    # After clearing, still resolves (re-parses on demand)
    assert c.find_function_at(str(src), 12) == "bar"


def test_missing_file_returns_empty(tmp_path: Path):
    c.clear_caches()
    assert c.find_function_at(str(tmp_path / "nope.c"), 1) == ""
