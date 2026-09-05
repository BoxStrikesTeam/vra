"""Call graph construction for VRA."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from vra.core.logging import get_logger

log = get_logger("analysis.callgraph")

# Matches a function definition, allowing a return type including pointers.
C_FUNC_RE = re.compile(
    r"(?:^|[\n;}])\s*(?:static\s+|extern\s+|inline\s+)*"
    r"(?:\w[\w:<>\s]*?){0,4}?[*\s]*\b(\w+)\s*\([^;{}]*\)\s*(?:const\s*)?\{",
    re.MULTILINE,
)
_CONTROL_KEYWORDS = {"if", "while", "for", "switch", "do", "return", "else", "typedef"}
CALL_RE = re.compile(r"\b(\w+)\s*\(")


_ENTRY_HINTS = ("main", "exit", "hook", "dispatch", "poll", "loop", "event", "handle", "init")


@dataclass
class CallGraph:
    functions: dict[str, list[str]] = field(default_factory=dict)
    function_files: dict[str, str] = field(default_factory=dict)
    entry_points: list[str] = field(default_factory=list)

    _reverse: dict[str, set[str]] = field(default_factory=dict, repr=False)
    _reachable: set[str] = field(default_factory=set, repr=False)
    _path_cache: dict[tuple[str, str], list[str] | None] = field(default_factory=dict, repr=False)

    def finalize(self) -> None:
        self._reverse = {}
        for caller, callees in self.functions.items():
            for callee in callees:
                self._reverse.setdefault(callee, set()).add(caller)
        self._compute_reachable()

    def _compute_reachable(self) -> None:
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
        """Return the shorted call chain from source to sink, cached per pair."""
        key = (source, sink)
        cached = self._path_cache.get(key)
        if cached is not None:
            return cached or None

        from collections import deque

        result: list[str] | None = None
        queue = deque([(source, [source])])
        visited = {source}
        while queue and result is None:
            current, path = queue.popleft()
            if current == sink:
                result = path
                break
            for callee in self.functions.get(current, ()):
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))
        self._path_cache[key] = result
        return result


class CallGraphBuilder:
    def __init__(self, source_dir: Path):
        self.source_dir = source_dir
        self.graph = CallGraph()

    def build(self) -> CallGraph:
        source_files = (
            list(self.source_dir.rglob("*.c"))
            + list(self.source_dir.rglob("*.cpp"))
            + list(self.source_dir.rglob("*.cc"))
        )
        if not source_files:
            return self.graph

        for file_path in source_files:
            if any(part.startswith(".") for part in file_path.relative_to(self.source_dir).parts):
                continue
            try:
                content = file_path.read_text(errors="ignore")
            except OSError:
                continue

            rel = str(file_path.relative_to(self.source_dir))

            function_defs = {}
            for match in C_FUNC_RE.finditer(content):
                func_name = match.group(1)
                if func_name in _CONTROL_KEYWORDS:
                    continue
                function_defs.setdefault(func_name, match.start())

            funcs_by_pos = sorted(function_defs.items(), key=lambda kv: kv[1])
            for idx, (func_name, start) in enumerate(funcs_by_pos):
                self.graph.functions.setdefault(func_name, [])
                self.graph.function_files[func_name] = rel
                if func_name in ("main",):
                    self.graph.entry_points.append(func_name)

                depth = 0
                end = len(content)
                for i in range(start, len(content)):
                    ch = content[i]
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break

                body = content[start:end]
                for call in CALL_RE.finditer(body):
                    callee = call.group(1)
                    if callee in function_defs and callee != func_name:
                        callees = self.graph.functions[func_name]
                        if callee not in callees:
                            callees.append(callee)

        if not self.graph.entry_points:
            for name in self.functions_alias(self.graph.functions):
                if name not in self.graph.entry_points:
                    self.graph.entry_points.append(name)
            self.graph.entry_points = self.graph.entry_points[:16]

        self.graph.finalize()
        log.info(
            "Built call graph: %d functions across %d files (%d entry points)",
            len(self.graph.functions),
            len(set(self.graph.function_files.values())),
            len(self.graph.entry_points),
        )
        return self.graph

    def functions_alias(self, functions: dict[str, list[str]]) -> list[str]:
        """Return likely entry functions by name hint, preserving definition order."""
        ordered = []
        for name in functions:
            low = name.lower()
            if low in ("main",) or "main" in low or any(h in low for h in _ENTRY_HINTS):
                ordered.append(name)
        if not ordered:
            ordered = list(functions)[:8]
        return ordered
