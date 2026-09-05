"""Confidence scoring for VRA."""

from __future__ import annotations

from vra.core.logging import get_logger
from vra.core.models import Finding

log = get_logger("correlation.confidence")


def adjust_confidence(finding: Finding) -> Finding:
    base = finding.confidence

    tool_count = len(finding.tools)
    if tool_count >= 3:
        base = min(base + 0.15, 1.0)
    elif tool_count >= 2:
        base = min(base + 0.10, 1.0)

    if finding.false_positive_indicators:
        penalty = min(0.1 * len(finding.false_positive_indicators), 0.3)
        base = max(base - penalty, 0.0)

    if finding.evidence:
        evidence_bonus = min(0.05 * len(finding.evidence), 0.15)
        base = min(base + evidence_bonus, 1.0)

    if finding.reachability and finding.reachability.value != "unknown":
        if finding.reachability.value == "high":
            base = min(base + 0.05, 1.0)
        elif finding.reachability.value == "low":
            base = max(base - 0.05, 0.0)

    finding.confidence = round(base, 3)
    return finding
