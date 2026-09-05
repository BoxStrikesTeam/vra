"""Crypto / PRNG misuse detection rule.

Flags common cryptographic pitfalls in C/C++:

* weak / predictable pseudo-random number generators (CWE-338)
* broken / obsolete hashes and ciphers such as MD5, SHA-1, DES, RC4 (CWE-327)
* hard-coded keys or secrets (CWE-798)

This is a deterministic, regex-based heuristic layer. It reports *potential*
issues with deliberately moderate confidence and never claims a confirmed
vulnerability from static evidence alone.
"""

from __future__ import annotations

import re

from vra.core.models import Finding, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

# --- Weak / predictable PRNG -------------------------------------------------
WEAK_RAND_CALL = re.compile(
    r"\b(rand|random|srand|lrand48|mrand48|drand48|rand_r)\s*\([^)]*\)",
    re.I,
)
SRAND_SEED_TIME = re.compile(
    r"\bsrand\s*\(\s*time\s*\([^)]*\)",
    re.I,
)

# --- Broken / obsolete algorithms -------------------------------------------
WEAK_HASH = re.compile(
    r"\b(MD5|MD5_Init|SHA1|SHA1_Init|EVP_md5|EVP_sha1|md5|sha1)\b",
    re.I,
)
WEAK_CIPHER = re.compile(
    r"\b(EVP_des|EVP_rc4|DES|RC4|Blowfish|bf_|CAST|AES_encrypt)\b",
    re.I,
)

# --- Hard-coded secrets ------------------------------------------------------
HARDCODED_KEY_DECL = re.compile(
    r"(?:const\s+)?(?:unsigned\s+)?char\s+\w*(?:key|secret|pass|token|iv)\w*\s*\[\s*\d*\s*\]\s*=\s*"
    r"\{\s*0x[0-9a-fA-F]+\s*(?:,\s*0x[0-9a-fA-F]+\s*){3,}",
    re.I,
)
HARDCODED_STRING = re.compile(
    r'(?:const\s+)?char\s+\w*(?:key|secret|pass|token)\w*\s*\[\s*\d*\s*\]\s*=\s*'
    r'"[^"]{4,}"',
    re.I,
)


@RuleRegistry.register
class SecureCryptoRule(SecurityRule):
    name = "crypto-misuse"
    category = "crypto"
    cwe = "CWE-338"
    description = (
        "Detects weak PRNGs, broken hash/cipher algorithms and "
        "hard-coded cryptographic material"
    )

    def analyze(self, context: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = context.file_content.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            if WEAK_HASH.search(line):
                findings.append(
                    self._make_finding(
                        title="Weak/obsolete hash algorithm (MD5/SHA-1) used",
                        severity="low",
                        confidence=0.45,
                        file=context.file_path,
                        line=i,
                    )
                )
                continue

            if WEAK_CIPHER.search(line):
                findings.append(
                    self._make_finding(
                        title="Weak/obsolete cipher (DES/RC4/Blowfish) used",
                        severity="medium",
                        confidence=0.5,
                        file=context.file_path,
                        line=i,
                    )
                )
                continue

            if HARDCODED_KEY_DECL.search(line) or HARDCODED_STRING.search(line):
                findings.append(
                    self._make_finding(
                        title="Hard-coded cryptographic key/secret detected",
                        severity="high",
                        confidence=0.6,
                        file=context.file_path,
                        line=i,
                    )
                )
                continue

            if SRAND_SEED_TIME.search(line) and "srand" in line.lower():
                findings.append(
                    self._make_finding(
                        title="Predictable PRNG seeded from time()",
                        severity="medium",
                        confidence=0.5,
                        file=context.file_path,
                        line=i,
                    )
                )
                continue

            if WEAK_RAND_CALL.search(line):
                findings.append(
                    self._make_finding(
                        title="Weak/predictable PRNG (rand/random) used",
                        severity="low",
                        confidence=0.35,
                        file=context.file_path,
                        line=i,
                    )
                )

        return findings
