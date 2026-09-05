"""C-accelerated backend for VRA's performance-critical routines.

This module exposes drop-in replacements for the pure-Python implementations
of call graph construction, function location, and snippet extraction. When the
compiled ``vra._native`` extension is available it is used; otherwise the pure
Python implementations are still viable (just slower).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from vra.core.logging import get_logger

log = get_logger("native")

try:  # pragma: no cover - depends on optional compiled artifact
    from vra import _native as _c  # type: ignore
    HAVE_NATIVE = True
except ImportError:  # pragma: no cover - fallback path
    _c = None
    HAVE_NATIVE = False


def native_available() -> bool:
    return HAVE_NATIVE


class NativeCallGraphBuilder:
    """Builds a call graph backed by the C extension.

    API-compatible with :class:`vra.analysis.callgraph.builder.CallGraphBuilder`
    for the fields the orchestrator consumes (functions, function_files,
    entry_points). Path finding and reachability are delegated to the C BFS.
    """

    def __init__(self, source_dir: Path):
        self.source_dir = Path(source_dir)
        self.functions: dict[str, list[str]] = {}
        self.function_files: dict[str, str] = {}
        self.entry_points: list[str] = []
        self._reverse: dict[str, set[str]] = {}
        self._reachable: set[str] = set()
        self._path_cache: dict[tuple[str, str], list[str] | None] = {}

    def build(self) -> "NativeCallGraphBuilder":
        result = _c.build_call_graph(str(self.source_dir))
        self.functions = result["functions"]
        self.function_files = result["function_files"]
        self.entry_points = list(result["entry_points"])

        if not self.entry_points:
            for name in self.functions:
                self.entry_points.append(name)
            self.entry_points = self.entry_points[:16]

        self.finalize()
        n_files = len({Path(p).name for p in self.function_files.values()})
        log.info(
            "Built native call graph: %d functions across %d files (%d entry points)",
            len(self.functions),
            n_files,
            len(self.entry_points),
        )
        return self

    def finalize(self) -> None:
        self._reverse = {}
        for caller, callees in self.functions.items():
            for callee in callees:
                self._reverse.setdefault(callee, set()).add(caller)
        from collections import deque

        reached: set[str] = set(self.entry_points)
        queue = deque(self.entry_points)
        while queue:
            current = queue.popleft()
            for callee in self.functions.get(current, ()):
                if callee not in reached:
                    reached.add(callee)
                    queue.append(callee)
        self._reachable = reached

    def reachable_from_entry(self, sink: str) -> bool:
        return sink in self._reachable

    def get_callers(self, function: str) -> list[str]:
        return list(self._reverse.get(function, ()))

    def build_path(self, source: str, sink: str) -> list[str] | None:
        key = (source, sink)
        if key in self._path_cache:
            return self._path_cache[key]
        path = _c.bfs_path(self.functions, source, sink)
        result = list(path) if path is not None else None
        self._path_cache[key] = result
        return result


@lru_cache(maxsize=4096)
def find_function_at(file_path: str, line: int) -> str:
    return _c.find_function_at(file_path, line)


@lru_cache(maxsize=4096)
def extract_snippet(file_path: str, line: int, context_lines: int = 15) -> str:
    return _c.extract_snippet(file_path, line, context_lines)


def clear_caches() -> None:
    find_function_at.cache_clear()
    extract_snippet.cache_clear()
    if HAVE_NATIVE:
        _c.clear_caches()


@lru_cache(maxsize=8)
def build_taint_data(source_dir: str) -> dict:
    """Extract per-function params/calls/assigns via the C extension."""
    return _c.build_taint_data(str(Path(source_dir)))
