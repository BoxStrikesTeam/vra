"""Structural validation for weak-PRNG findings (CWE-338).

``rand()``/``random()`` are only a real risk when their output feeds a security
decision (token/key/nonce/salt/hash/signature). Benchmarks, jitter, backoff and
test code are false positives. We demote when no security-sensitive use is
visible in the surrounding function.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome
from vra.rules.validation.memory_leak import _window
from vra.rules.validation.signals import strip_comments

_SECURITY_CONTEXT = re.compile(
    r"\b(token|nonce|salt|key|password|passwd|signature|secret|cookie|session|csrf|hmac|hash|otp)\b",
    re.IGNORECASE,
)
_RAND_CALL = re.compile(r"\b(rand|random|srand|lrand48|mrand48|drand48|rand_r)\s*\(")


class WeakRandomValidator(SecurityValidator):
    name = "weak-random"
    categories = ("crypto", "prng")
    cwes = ("CWE-338",)

    def __init__(self, strict: bool = False):
        self.strict = strict

    def validate(self, finding: Finding, source_content: str, source_dir: Path) -> ValidationOutcome:
        block = strip_comments(_window(source_content, finding.source.line, radius=40))
        if not _RAND_CALL.search(block):
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="No PRNG call found in context; skipping.",
            )

        if _SECURITY_CONTEXT.search(block):
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="PRNG value may feed a security-sensitive decision.",
            )

        return self._fp(
            "PRNG output is not used in a security-sensitive context here.",
            "PRNG used outside a security-sensitive context",
        )

    @staticmethod
    def _fp(reason: str, indicator: str) -> ValidationOutcome:
        return ValidationOutcome(
            verdict=ValidationResult.LIKELY_FP,
            reason=reason,
            indicators=[indicator],
        )
