"""Finding fingerprinting and deduplication for VRA."""

from __future__ import annotations

import hashlib

from vra.core.logging import get_logger
from vra.core.models import Finding

log = get_logger("correlation.fingerprint")


def compute_fingerprint(finding: Finding) -> str:
    parts = [
        finding.source.file,
        str(finding.source.line),
        finding.source.function,
        finding.cwe,
        finding.title.lower().strip(),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def compute_fingerprint_from_parts(file: str, line: int, function: str, cwe: str, title: str) -> str:
    parts = [file, str(line), function, cwe, title.lower().strip()]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
