"""Project inspection and detection for VRA."""

from __future__ import annotations

import subprocess
from pathlib import Path

from vra.core.enums import BuildSystemType
from vra.core.logging import get_logger
from vra.core.models import ProjectInfo

log = get_logger("project.inspector")


def inspect_project(path: Path) -> ProjectInfo:
    path = path.resolve()
    info = ProjectInfo(path=path, name=path.name)

    c_extensions = {".c", ".cc", ".cx", ".cxx"}
    cpp_extensions = {
        ".cpp",
        ".cc",
        ".cxx",
        ".C",
        ".c++",
        ".hpp",
        ".hxx",
        ".hh",
        ".h++",
        ".ipp",
        ".tpp",
    }
    header_extensions = {".h", ".hpp", ".hxx", ".hh"}

    c_files = 0
    cpp_files = 0
    header_files = 0
    total = 0

    for f in path.rglob("*"):
        if f.is_file() and not any(part.startswith(".") for part in f.relative_to(path).parts):
            ext = f.suffix.lower()
            if ext in c_extensions:
                c_files += 1
                total += 1
            elif ext in cpp_extensions:
                cpp_files += 1
                total += 1
            elif ext in header_extensions:
                header_files += 1
                total += 1

    info.c_files = c_files
    info.cpp_files = cpp_files
    info.header_files = header_files
    info.total_files = total

    if total > 0:
        info.c_ratio = c_files / total
        info.cpp_ratio = cpp_files / total

    if c_files > 0 or cpp_files > 0:
        if c_files > cpp_files:
            info.languages = ["C"]
        elif cpp_files > c_files:
            info.languages = ["C++"]
        else:
            info.languages = ["C", "C++"]
    else:
        info.languages = []

    info.build_system = _detect_build_system(path)
    info.compiler = _detect_compiler()
    info.architecture = _detect_architecture()
    info.has_tests = _detect_tests(path)
    info.has_network_code = _detect_pattern(path, ["socket", "recv", "send", "bind", "listen", "accept", "connect"])
    info.has_parser_code = _detect_pattern(path, ["parse", "tokenizer", "lexer", "decoder", "deserialize"])
    info.has_ipc_code = _detect_pattern(path, ["pipe", "shmget", "mmap", "fork", "msgget"])
    info.has_privileged_code = _detect_pattern(path, ["setuid", "setgid", "sudo", "capability", "privilege"])

    executables, shared_libs, static_libs = _count_artifacts(path)
    info.executable_count = executables
    info.shared_lib_count = shared_libs
    info.static_lib_count = static_libs

    log.info(
        "Project '%s' inspected: %s, build=%s, files=%d",
        info.name,
        info.languages,
        info.build_system.value,
        total,
    )
    return info


def _detect_build_system(path: Path) -> BuildSystemType:
    if (path / "CMakeLists.txt").exists():
        return BuildSystemType.CMAKE
    if (path / "meson.build").exists():
        return BuildSystemType.MESON
    if (path / "configure.ac").exists() or (path / "configure.in").exists():
        return BuildSystemType.AUTOTOOLS
    if (path / "Makefile").exists() or (path / "GNUmakefile").exists():
        return BuildSystemType.MAKE
    return BuildSystemType.UNKNOWN


def _detect_compiler() -> str:
    for compiler in ["clang", "gcc", "cc"]:
        try:
            result = subprocess.run(
                [compiler, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                first_line = result.stdout.strip().split("\n")[0]
                return first_line
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return "unknown"


def _detect_architecture() -> str:
    try:
        result = subprocess.run(["uname", "-m"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def _detect_tests(path: Path) -> bool:
    test_indicators = ["test", "tests", "spec", "check", "CTestTestfile"]
    for indicator in test_indicators:
        if list(path.glob(f"*{indicator}*")):
            return True
        if list(path.rglob(f"*{indicator}*")):
            return True
    return False


def _detect_pattern(path: Path, patterns: list[str], max_files: int = 50) -> bool:
    count = 0
    for f in path.rglob("*.{c,cpp,cc,cxx,h,hpp}"):
        if count >= max_files:
            break
        try:
            content = f.read_text(errors="ignore")[:8192]
            for pattern in patterns:
                if pattern in content:
                    return True
            count += 1
        except (OSError, PermissionError):
            continue
    return False


def _count_artifacts(path: Path) -> tuple[int, int, int]:
    executables = 0
    shared_libs = 0
    static_libs = 0
    for f in path.rglob("*"):
        if f.is_file():
            name = f.name.lower()
            if name.endswith((".so", ".dylib", ".dll")):
                shared_libs += 1
            elif name.endswith(".a"):
                static_libs += 1
    return executables, shared_libs, static_libs


def get_repository_info(path: Path) -> dict[str, str]:
    info: dict[str, str] = {}
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["remote_url"] = result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["commit_hash"] = result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            info["branch"] = result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return info


# Directories conventionally treated as third-party / vendored code.
_VENDORED_DIR_NAMES = {
    "3rdparty",
    "third_party",
    "third-party",
    "vendor",
    "vendored",
    "external",
    "deps",
    "contrib",
    "lib",
    "libs",
    "extern",
    "thirdparty",
    "bundled",
}


def is_vendored_path(rel_parts: list[str]) -> bool:
    """Return True if any path component marks the file as third-party.

    Matches by directory name only (e.g. ``src/3rdparty/sqlite3.c``). Header
    directories such as ``include`` are intentionally excluded so that a
    project's own headers are not misclassified.
    """
    for part in rel_parts:
        if part in _VENDORED_DIR_NAMES:
            return True
    return False


def vendored_hint(path: Path, project_root: Path) -> str | None:
    """Return a short human description for a vendored file, else None.

    Example: file under ``3rdparty`` returns ``3rdparty (vendored/third-party)``.
    """
    try:
        rel = path.resolve().relative_to(project_root.resolve())
    except ValueError:
        return None
    parts = rel.parts[:-1]
    for part in parts:
        if part in _VENDORED_DIR_NAMES:
            return f"{part} (vendored/third-party)"
    return None
