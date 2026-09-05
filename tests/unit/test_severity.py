"""Unit tests for severity and priority scoring."""

from vra.core.enums import ControllabilityLevel, ReachabilityLevel, Severity
from vra.core.models import Finding, SourceLocation
from vra.security.prioritizer import prioritize_findings
from vra.security.severity import calculate_priority_score


def _make_finding(
    severity=Severity.HIGH,
    confidence=0.9,
    reachability=ReachabilityLevel.HIGH,
    controllability=ControllabilityLevel.HIGH,
):
    return Finding(
        id="",
        title="Test",
        category="memory",
        cwe="CWE-120",
        severity=severity,
        confidence=confidence,
        source=SourceLocation(file="main.c", line=10, function="main"),
        tools=["codeql", "clang"],
        reachability=reachability,
        controllability=controllability,
    )


def test_high_risk_scores_high():
    f = _make_finding()
    score = calculate_priority_score(f)
    assert score > 7.0


def test_low_risk_scores_low():
    f = _make_finding(severity=Severity.LOW, confidence=0.2)
    score = calculate_priority_score(f)
    assert score < 5.0


def test_priority_scores_bounded():
    f = _make_finding(severity=Severity.CRITICAL, confidence=1.0)
    score = calculate_priority_score(f)
    assert score <= 10.0


def test_prioritize_sorts_by_score():
    low = _make_finding(severity=Severity.LOW, confidence=0.2)
    high = _make_finding()
    findings = prioritize_findings([low, high])
    assert findings[0] == high
