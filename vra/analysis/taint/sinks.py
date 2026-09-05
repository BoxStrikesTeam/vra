"""Sink definitions for VRA taint analysis.

A *sink* is a sensitive call whose arguments, if attacker-controlled, produce a
vulnerability. Each sink maps to the argument positions that matter, plus an
optional CWE and note describing why it is risky.

The return value is a list of `SinkSpec` describing the risky argument indices
(0-based, or -1 for "all arguments").
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SinkSpec:
    call: str
    risky_args: list[int] = field(default_factory=list)
    cwe: str = "CWE-0"
    desc: str = ""
    # -1 arg index means "every argument is risky" (e.g. variadic)
    all_args: bool = False

    def arg_is_risky(self, idx: int) -> bool:
        if self.all_args:
            return True
        return idx in self.risky_args


# Ordered list of known sinks. Earlier entries take precedence on name match.
SINKS: list[SinkSpec] = [
    # Memory copy / move
    SinkSpec("memcpy", [2], "CWE-120", "Uncontrolled count or source length"),
    SinkSpec("memmove", [2], "CWE-120", "Uncontrolled count or source length"),
    SinkSpec("memset", [2], "CWE-120", "Uncontrolled count"),
    SinkSpec("memcmp", [2], "CWE-190", "Uncontrolled length"),
    # String copy / splice
    SinkSpec("strcpy", [1], "CWE-120", "Unbounded source string"),
    SinkSpec("strcat", [1], "CWE-120", "Unbounded source string"),
    SinkSpec("strncpy", [2], "CWE-120", "Length derived from source"),
    SinkSpec("strncat", [2], "CWE-120", "Length derived from source"),
    # Formatted output / input
    SinkSpec("sprintf", [1, 2], "CWE-134", "Format string and args"),
    SinkSpec("vsprintf", [1, 2], "CWE-134", "Format string and args"),
    SinkSpec("sprintf_s", [], "CWE-134", "Format string"),
    SinkSpec("scanf", [-1], "CWE-120", "Untrusted formatted read", all_args=True),
    SinkSpec("sscanf", [1], "CWE-120", "Untrusted source string"),
    SinkSpec("vsscanf", [1], "CWE-120", "Untrusted source string"),
    # Command execution
    SinkSpec("system", [-1], "CWE-78", "Shell command", all_args=True),
    SinkSpec("popen", [-1], "CWE-78", "Shell command", all_args=True),
    SinkSpec("execl", [-1], "CWE-78", "Executable path", all_args=True),
    SinkSpec("execlp", [-1], "CWE-78", "Executable path", all_args=True),
    SinkSpec("execle", [-1], "CWE-78", "Executable path", all_args=True),
    SinkSpec("execv", [0], "CWE-78", "Executable path"),
    SinkSpec("execvp", [0], "CWE-78", "Executable path"),
    SinkSpec("posix_spawn", [1], "CWE-78", "Executable path"),
    # File / path
    SinkSpec("open", [0], "CWE-22", "Untrusted path"),
    SinkSpec("fopen", [0], "CWE-22", "Untrusted path"),
    SinkSpec("remove", [0], "CWE-22", "Untrusted path"),
    SinkSpec("unlink", [0], "CWE-22", "Untrusted path"),
    # SQL (for completeness; C-family rarely)
    SinkSpec("sqlite3_exec", [-1], "CWE-89", "SQL statement", all_args=True),
    SinkSpec("sqlite3_prepare_v2", [1], "CWE-89", "SQL statement"),
    SinkSpec("sqlite3_snprintf", [], "CWE-89", "SQL formatting"),
    # Misc
    SinkSpec("malloc", [0], "CWE-190", "Attacker-controlled allocation size"),
    SinkSpec("realloc", [1], "CWE-190", "Attacker-controlled allocation size"),
    SinkSpec("alloca", [0], "CWE-190", "Attacker-controlled allocation size"),
    SinkSpec("calloc", [0, 1], "CWE-190", "Attacker-controlled allocation size"),
    SinkSpec("setenv", [0], "CWE-77", "Untrusted env name"),
    SinkSpec("strlen", [0], "CWE-190", "Length over attacker data"),
]

# Special sink kinds produced by pattern scans rather than simple name lookup.
INDICES_INDEX_NAME = "array_index"
ALLOC_OVERFLOW_NAME = "alloc_overflow"

INDEX_SINK = SinkSpec(INDICES_INDEX_NAME, [-1], "CWE-787", "Array index derived from tainted data")
ALLOC_OVERFLOW_SINK = SinkSpec(
    ALLOC_OVERFLOW_NAME, [0], "CWE-120", "Allocation size (or factor) derived from tainted data"
)

# Quick lookup
SINK_BY_NAME: dict[str, SinkSpec] = {}
for _s in SINKS:
    SINK_BY_NAME.setdefault(_s.call, _s)


def find_sink(name: str, args: list[str]) -> SinkSpec | None:
    """Return the matching sink spec, or None if not a known sink.

    A heuristic also flags sink-like calls whose name begins with a dangerous
    stem (e.g. `my_sprintf`).
    """
    if name in SINK_BY_NAME:
        return SINK_BY_NAME[name]

    # Heuristic allowances for wrapper sinks.
    lowered = name.lower()
    for stem in (
        "memcpy",
        "memmove",
        "strcpy",
        "strcat",
        "sprintf",
        "system",
        "scanf",
        "fscanf",
        "popen",
        "exec",
    ):
        if lowered.startswith(stem):
            return SinkSpec(name, [], "CWE-120", f"Wrapper around {stem}")
    if args:
        if lowered.startswith("sqlite3"):
            return SinkSpec(name, [], "CWE-89", "SQLite sink")
    return None
