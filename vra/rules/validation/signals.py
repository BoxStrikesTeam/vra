"""Shared structural-validation signals used across the validators.

Earlier validators collapsed all context down to ``bool(finding.dataflow)``.
These helpers expose the *root source* of a taint path (the ``(network)`` /
``(cli)`` tags embedded in dataflow step descriptions) plus small text-hygiene
utilities, so every validator reasons from the same, accurate signals.
"""

from __future__ import annotations

import re

from vra.core.enums import ControllabilityLevel
from vra.core.models import Finding

#: step description tags that denote an attacker-relevant boundary
_ATTACKER_SOURCES = {
    "network",
    "packet",
    "socket",
    "ipc",
    "plugin",
    "privileged",
    "privileged_service",
    "remote",
}

#: tags that only describe ambient / operator / build-time data
_AMBIENT_SOURCES = {
    "cli",
    "config",
    "configuration",
    "environment",
    "env",
    "static",
    "constant",
    "library",
    "library_api",
}

_TAG_RE = re.compile(r"\(([a-z_]+)\)")

_INDEX_INTO = re.compile(
    r"used as (?:an\s+)?index\s+(?:into|for|on)\s+[`']?([A-Za-z_]\w*)[`']?"
)

# --- pointer dereference / null-check signal (shared by the UAF rule+validator) ---

_NULL_CHECK = re.compile(r"\b(?:if|while)\s*\([^)]*!\s*(\w+)\s*\)")
_PTR_NULL_EQ = re.compile(r"\b(\w+)\s*(?:==\s*NULL|NULL\s*==|!=?\s*NULL)")


def is_null_check(line: str, ptr: str) -> bool:
    """True when ``line`` only guards/compares ``ptr`` without dereferencing it."""
    for pat in (_NULL_CHECK, _PTR_NULL_EQ):
        m = pat.search(line)
        if m and m.group(1) == ptr:
            return True
    return bool(re.search(rf"\b(?:if|while|assert)\s*\(\s*!?\s*{re.escape(ptr)}\s*\)", line))


def deref_pattern(ptr: str) -> re.Pattern[str]:
    """Regex matching a genuine dereference/consumption of ``ptr`` on a line:
    ``ptr->x``, ``ptr[i]``, ``*ptr``, or an argument to a non-control-flow call."""
    p = re.escape(ptr)
    return re.compile(
        rf"\b{p}\s*(?:->|\[|\.)"  # ptr->x | ptr[i] | ptr.field
        rf"|\*\s*{p}\b"  # *ptr
        # used as an argument to a call (excluding if/while/for/switch/assert)
        rf"|\b(?!(?:if|while|for|switch|assert|sizeof)\b)[A-Za-z_]\w*\s*\(\s*{p}\s*(?:,|\))"
    )


def root_source_tags(finding: Finding) -> set[str]:
    """Collect the ``(tag)`` boundary hints embedded in the dataflow steps."""
    tags: set[str] = set()
    for step in finding.dataflow:
        for m in _TAG_RE.finditer(step.description or ""):
            tag = m.group(1).lower()
            if tag and tag != "line":
                tags.add(tag)
    return tags


def attacker_root(finding: Finding) -> bool:
    """True when any taint step reaches an attacker-relevant boundary."""
    return bool(root_source_tags(finding) & _ATTACKER_SOURCES)


def ambient_only(finding: Finding) -> bool:
    """True when every root tag is ambient (cli/config/env/static/library)."""
    tags = root_source_tags(finding)
    if not tags:
        return False
    return not (tags & _ATTACKER_SOURCES)


def low_controllability(finding: Finding) -> bool:
    """True when controllability is low, unknown or unset."""
    ctrl = getattr(finding, "controllability", None)
    if isinstance(ctrl, str):
        ctrl = ControllabilityLevel(ctrl)
    return ctrl in (ControllabilityLevel.LOW, ControllabilityLevel.UNKNOWN, None)


def index_target(finding: Finding) -> str | None:
    """Name of the array being indexed, from the dataflow step descriptions.

    Taint steps carry lines like ``"tainted value used as index into 'anLt'"``;
    the last such step names the buffer we should bounds-check.
    """
    for step in reversed(finding.dataflow):
        m = _INDEX_INTO.search(step.description or "")
        if m:
            return m.group(1)
    return None


def strip_comments(text: str) -> str:
    """Remove block/line comments and string literals so pattern matching
    does not fire on documentation or quoted text."""
    if not text:
        return text
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)
    text = re.sub(r"'(?:[^'\\]|\\.)*'", "''", text)
    lines = []
    for line in text.splitlines():
        idx = line.find("//")
        lines.append(line if idx == -1 else line[:idx])
    return "\n".join(lines)


def window(content: str, line: int, radius: int = 80) -> str:
    """Standard context window around ``line`` (re-exported for consistency)."""
    from vra.rules.validation.memory_leak import _window

    return _window(content, line, radius)
