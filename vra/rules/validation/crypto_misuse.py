"""Structural validation for crypto-misuse findings (CWE-338, CWE-327, CWE-798).

Weak PRNG / weak cipher / hard-coded key findings are FP-prone when the crypto
is used in a non-security capacity (test fixtures, UI animation seeds). We look
for evidence that the weak primitive feeds a security-relevant API (encrypt,
sign, keygen, TLS, password) within the adjacent source window.
"""

from __future__ import annotations

import re
from pathlib import Path

from vra.core.enums import ValidationResult
from vra.core.models import Finding
from vra.rules.validation.base import SecurityValidator, ValidationOutcome
from vra.rules.validation.memory_leak import _window

_SECURITY_USAGE = re.compile(
    r"\b(encrypt|decrypt|sign|verify|sha|aes|rsa|ssl|tls|keygen|"
    r"derive|PBKDF|HKDF|password|credential|token|seed)\b",
    re.IGNORECASE,
)
_WEAK_PRNG = re.compile(r"\b(rand|srand|random|rand_r|random_r)\b")
_HARDCODED = re.compile(r"\b(key|secret|password|token|iv)\s*\[?=>=]?\s*[\"']")


class CryptoMisuseValidator(SecurityValidator):
    name = "crypto-misuse"
    categories = ("crypto",)
    cwes = ("CWE-338", "CWE-327", "CWE-798")

    def validate(
        self, finding: Finding, source_content: str, source_dir: Path
    ) -> ValidationOutcome:
        block = _window(source_content, finding.source.line)

        # Hard-coded key/secret: inherently FP only if used for non-security.
        if "CWE-798" in (finding.cwe or ""):
            if _SECURITY_USAGE.search(block):
                return ValidationOutcome(
                    verdict=ValidationResult.CONFIRMED,
                    reason="Hard-coded credential feeds a security-relevant API.",
                )
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Hard-coded value present; security purpose not confirmed.",
            )

        # Weak PRNG / cipher: confirmed if adjacent to security usage.
        if _WEAK_PRNG.search(finding.source_snippet or "") and _SECURITY_USAGE.search(block):
            return ValidationOutcome(
                verdict=ValidationResult.CONFIRMED,
                reason="Weak randomness is used in a security-relevant context.",
            )

        if _WEAK_PRNG.search(finding.source_snippet or ""):
            if _SECURITY_USAGE.search(block) and _HARDCODED.search(block):
                return ValidationOutcome(
                    verdict=ValidationResult.CONFIRMED,
                    reason="Weak PRNG near credential/key material.",
                )
            return ValidationOutcome(
                verdict=ValidationResult.SUSPICIOUS,
                reason="Weak PRNG found, but security usage not proven.",
            )

        return ValidationOutcome(
            verdict=ValidationResult.SUSPICIOUS,
            reason="Crypto primitive present; requires manual review.",
        )
