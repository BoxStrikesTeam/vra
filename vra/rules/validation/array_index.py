"""Structural validation for out-of-bounds array-index findings (CWE-787 / CWE-125).

The dominant FP class in C-like parsers: the taint engine flags *every*
``buf[i]`` write whose index value ever touches a ``(network)``-rooted flow,
even when the index is a loop counter bounded by a constant, a fixed-size local
buffer, or stems from an ambient (cli/config) source. We demote only when we can
*prove* the access is bounded; an attacker-rooted index with no visible bound
stays confirmed.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome
from vra.rules.validation.memory_leak import _window
from vra.rules.validation.signals import (
    ambient_only,
    attacker_root,
    index_target,
    low_controllability,
    strip_comments,
)

# for (i = ...; i < 64; ...)  |  while (i < 64)  |  if (i < 64)
_CONST_BOUND = re.compile(
    r"\b(?:for|while|if)\s*\([^;{}]{0,90}?\b([A-Za-z_]\w*)\s*(?:<|<=)\s*(\d+|\b0x[0-9a-fA-F]+)\b"
)
# loop/guard comparing the index against sizeof(array)
_SIZEOF_BOUND = re.compile(
    r"\b(?:for|while|if)\s*\([^;{}]{0,90}?\b([A-Za-z_]\w*)\s*(?:<|<=)\s*"
    r"sizeof\s*\(\s*[A-Za-z_]\w*\s*\)"
)
# fixed-size local buffer declaration, e.g. "char buf[64];"
_DECL_FIXED = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]\s*[=;{]")


class ArrayIndexValidator(SecurityValidator):
    name = "array-index"
    categories = ("input", "taint", "memory", "boundary")
    cwes = ("CWE-787", "CWE-125")

    def __init__(self, strict: bool = False):
        self.strict = strict

    def validate(
        self, finding: Finding, source_content: str, source_dir: Path
    ) -> ValidationOutcome:
        block = strip_comments(_window(source_content, finding.source.line))
        taint_path = bool(finding.dataflow)
        ctrl_low = low_controllability(finding)
        root_attacker = attacker_root(finding)
        target = index_target(finding) or _declared_array_hint(block)

        # 1. No provenance connects any input to this index.
        if not taint_path and ctrl_low:
            return self._fp(
                "No dataflow connects attacker input to this index.",
                "index not tracked to an attacker-controlled source",
            )

        # 2. Taint claimed, but every root is ambient (cli/config/...).
        if ambient_only(finding):
            return self._fp(
                "Index taint stems only from ambient sources (cli/config).",
                "index taint is ambient-only, not attacker input",
            )

        const_bound = _const_bound_for(block, target)
        sizeof_bound = _SIZEOF_BOUND.search(block) is not None
        fits_fixed_decl = target is not None and _fits_fixed_decl(block, target, const_bound)

        # 3. A constant bound in the same function makes the access provably
        #    in-bounds for low/ambient controllability.
        if const_bound is not None and (ctrl_low or ambient_only(finding)):
            return self._fp(
                "Index is bounded by a constant comparison within the same function.",
                "index bounded by constant comparison",
            )
        if sizeof_bound and ctrl_low:
            return self._fp(
                "Index is bounded by sizeof(array) within the same function.",
                "index bounded by sizeof(array)",
            )
        if fits_fixed_decl:
            return self._fp(
                f"Index into '{target}' fits the fixed-size local buffer.",
                "index bounded by fixed-size local buffer",
            )

        # 4. Strict mode: absence of an attacker root is demotion-worthy even
        #    with dataflow present.
        if self.strict and not root_attacker and taint_path:
            return self._fp(
                "No attacker-relevant taint root found for this index.",
                "no attacker-relevant source for index taint",
            )

        # 5. Genuinely attacker-rooted index with no visible bound.
        if root_attacker and not const_bound and not sizeof_bound:
            return ValidationOutcome(
                verdict=ValidationResult.CONFIRMED,
                reason="Index is attacker-influenced with no visible bounds check.",
            )
        if const_bound or sizeof_bound:
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="A bounds check exists; depends on runtime values.",
            )
        return ValidationOutcome(
            verdict=ValidationResult.SUSPICIOUS,
            reason="No provable bound; index influence cannot be dismissed.",
        )

    @staticmethod
    def _fp(reason: str, indicator: str) -> ValidationOutcome:
        return ValidationOutcome(
            verdict=ValidationResult.LIKELY_FP,
            reason=reason,
            indicators=[indicator],
        )


def _const_bound_for(block: str, target: str | None) -> int | None:
    """Numeric constant from a loop/guard bound over the index variable."""
    for m in _CONST_BOUND.finditer(block):
        value = m.group(2)
        try:
            return int(value, 0)
        except ValueError:
            continue
    return None


def _declared_array_hint(block: str) -> str | None:
    m = _DECL_FIXED.search(block)
    return m.group(1) if m else None


def _fits_fixed_decl(block: str, target: str, bound: int | None) -> bool:
    """True when ``target[N]`` is declared with N >= the constant bound."""
    for m in _DECL_FIXED.finditer(block):
        if m.group(1) == target:
            try:
                size = int(m.group(2), 0)
            except ValueError:
                continue
            if bound is not None and size >= bound:
                return True
            # constant bound missing: a fixed-size decl is still strong
            # evidence when controllability is low (handled by caller).
    return False
