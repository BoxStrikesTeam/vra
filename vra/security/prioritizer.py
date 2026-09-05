"""Risk prioritizer for VRA."""

from __future__ import annotations

from vra.core.logging import get_logger
from vra.core.models import Finding
from vra.security.severity import calculate_priority_score

log = get_logger("security.prioritizer")


def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        finding.priority_score = calculate_priority_score(finding)

    findings.sort(key=lambda f: f.priority_score, reverse=True)

    log.info("Prioritized %d findings", len(findings))
    return findings
