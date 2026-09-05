"""Sanitizer / guard detection for VRA taint.

A sanitizer either bounds the risky input (length/size checks) or uses a
bounds-checked wrapper instead of the raw sink. If a sanitizer is present we
downgrade controllability to LOW (or mark the finding as likely a false
positive).

This is a *practical* model: it recognises common defensive patterns, not a
full data-flow proof.
"""

from __future__ import annotations

import re

# --- Length/size guard expressions seen in the surrounding context ---------
SIZE_GUARD_RE = re.compile(
    r"\bif\s*\([^)]*(?:sizeof\s*\(|len(?:gth)?\s*[<>=]|size\s*[<>=]|n\s*[<>=]|"
    r"MAX_|<=\s*(?:sizeof))",
    re.I,
)

# --- Bounded alternative sinks (drop in for unbounded ones) ----------------
BOUNDED_ALTERNATIVES = {
    "strcpy": ("strlcpy", "strncpy"),
    "strcat": ("strlcat", "strncat"),
    "sprintf": ("snprintf", "vsnprintf"),
    "vsprintf": ("vsnprintf",),
}

SAFE_SINK_NAMES = {
    "snprintf",
    "vsnprintf",
    "strlcpy",
    "strlcat",
    "strncpy",
    "strncat",
}

# A guard immediately preceding the sink on the same line or nearby.
GUARD_NEARBY_RE = re.compile(r"\bif\s*\(|while\s*\(|<=|>=|<\s*sizeof|==\s*sizeof")


def has_bounded_wrapper(name: str) -> bool:
    """Whether this sink has a bounds-checked alternative we recognised."""
    return name in BOUNDED_ALTERNATIVES


def look_for_guard(context_lines: list[str]) -> bool:
    """Return True if any surrounding statement suggests an explicit bounds check."""
    for line in context_lines:
        if SIZE_GUARD_RE.search(line):
            return True
    return False


def is_safe_alternative(name: str) -> bool:
    return name in SAFE_SINK_NAMES
