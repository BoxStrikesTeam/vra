"""Unit tests for project detection."""

from pathlib import Path

from vra.core.enums import BuildSystemType
from vra.project.inspector import _detect_build_system, inspect_project


def test_detect_cmake(tmp_path: Path):
    (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.0)")
    assert _detect_build_system(tmp_path) == BuildSystemType.CMAKE


def test_detect_meson(tmp_path: Path):
    (tmp_path / "meson.build").write_text("project('test')")
    assert _detect_build_system(tmp_path) == BuildSystemType.MESON


def test_detect_make(tmp_path: Path):
    (tmp_path / "Makefile").write_text("all:\n\techo hi")
    assert _detect_build_system(tmp_path) == BuildSystemType.MAKE


def test_detect_unknown(tmp_path: Path):
    assert _detect_build_system(tmp_path) == BuildSystemType.UNKNOWN


def test_inspect_project_counts_files(tmp_path: Path):
    (tmp_path / "main.c").write_text("int main(void) { return 0; }")
    (tmp_path / "lib.cpp").write_text("int add(int a, int b) { return a + b; }")
    info = inspect_project(tmp_path)
    assert info.c_files == 1
    assert info.cpp_files == 1
    assert "C" in info.languages
    assert "C++" in info.languages
