"""Severity calculation for VRA."""

from __future__ import annotations

from vra.core.enums import Severity
from vra.core.logging import get_logger
from vra.core.models import Finding

log = get_logger("security.severity")

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 4.0,
    Severity.HIGH: 3.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 1.0,
}


def calculate_priority_score(finding: Finding) -> float:
    sev_weight = SEVERITY_WEIGHT.get(finding.severity, 1.0)
    conf = finding.confidence

    reachability_bonus = 0.0
    if finding.reachability.value == "high":
        reachability_bonus = 0.15
    elif finding.reachability.value == "medium":
        reachability_bonus = 0.08
    elif finding.reachability.value == "low":
        reachability_bonus = 0.03

    controllability_bonus = 0.0
    if finding.controllability.value == "high":
        controllability_bonus = 0.15
    elif finding.controllability.value == "medium":
        controllability_bonus = 0.08

    tool_bonus = min(0.05 * len(finding.tools), 0.15)

    raw_score = (sev_weight * 2.5) * conf + reachability_bonus * 10 + controllability_bonus * 10 + tool_bonus * 10
    score = min(raw_score, 10.0)

    return round(score, 1)
