"""Security classification for VRA."""

from __future__ import annotations

from vra.core.enums import Severity
from vra.core.models import Finding


def classify_finding_category(finding: Finding) -> str:
    cwe = finding.cwe
    if cwe in ("CWE-119", "CWE-120", "CWE-131", "CWE-416", "CWE-415"):
        return "memory-safety"
    if cwe in ("CWE-190",):
        return "integer-safety"
    if cwe in ("CWE-476",):
        return "null-safety"
    if cwe in ("CWE-401", "CWE-404"):
        return "resource-management"
    if cwe in ("CWE-502",):
        return "deserialization"
    if cwe in ("CWE-20",):
        return "input-validation"
    if cwe in ("CWE-252",):
        return "error-handling"
    return "general"


def get_severity_label(severity: Severity) -> str:
    labels = {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
    }
    return labels.get(severity, "Unknown")
