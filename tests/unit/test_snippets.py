"""Unit tests for snippet extraction caching."""

from __future__ import annotations

from pathlib import Path

from vra.evidence.snippets import clear_cache, extract_snippet


def test_snippet_extraction_keylines(tmp_path: Path):
    src = tmp_path / "sample.c"
    src.write_text("line1\nline2\nline3\nline4\nline5\n")
    clear_cache()
    snippet = extract_snippet(str(src), 3)
    assert ">>>" in snippet
    assert "3 |" in snippet


def test_snippet_missing_file_returns_empty(tmp_path: Path):
    clear_cache()
    assert extract_snippet(str(tmp_path / "nope.c"), 1) == ""


def test_snippet_cache_reused(tmp_path: Path):
    src = tmp_path / "a.c"
    src.write_text("x\ny\nz\n")
    clear_cache()
    first = extract_snippet(str(src), 2)
    second = extract_snippet(str(src), 2)
    assert first == second
