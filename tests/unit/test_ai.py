"""Unit tests for the LocalAIProvider narrative engine."""

from __future__ import annotations

import types

from vra.ai.local import LocalAIProvider
from vra.core.enums import ControllabilityLevel, ReachabilityLevel, Severity


def _make_finding(**overrides):
    defaults = {
        "id": "F-00001",
        "title": "Use After Free in process_msg",
        "category": "memory",
        "cwe": "CWE-416",
        "severity": Severity.HIGH,
        "confidence": 0.85,
        "priority_score": 8.2,
        "source": types.SimpleNamespace(file="src/main.c", line=42, function="process_msg"),
        "tools": ["clang"],
        "call_chain": [types.SimpleNamespace(function="main")],
        "source_snippet": "code",
        "reachability": ReachabilityLevel.HIGH,
        "controllability": ControllabilityLevel.HIGH,
        "false_positive_indicators": [],
    }
    defaults.update(overrides)
    return types.SimpleNamespace(**defaults)


def _project(name="pwnkit-probe"):
    return types.SimpleNamespace(name=name)


def test_analyze_produces_executive_summary():
    provider = LocalAIProvider()
    findings = [_make_finding()]
    analysis = provider.analyze_findings(findings, _project())

    assert analysis.executive_summary
    assert "pwnkit-probe" in analysis.executive_summary
    assert "candidate" in analysis.executive_summary.lower()


def test_analyze_uses_cautious_language():
    provider = LocalAIProvider()
    findings = [_make_finding()]
    analysis = provider.analyze_findings(findings, _project())

    text = analysis.executive_summary + " " + " ".join(analysis.recommendations)
    assert "confirmed vulnerability" not in text
    assert "payload" not in text.lower()
    assert "exploit code" not in text.lower()
    assert "manual validation" in analysis.disclaimer.lower()


def test_analyze_creates_narrative_with_cwe_description():
    provider = LocalAIProvider()
    findings = [_make_finding()]
    analysis = provider.analyze_findings(findings, _project())

    assert len(analysis.narratives) == 1
    narrative = analysis.narratives[0]
    assert narrative.finding_id == "F-00001"
    assert narrative.cwe == "CWE-416"
    assert "Use After Free" in narrative.cwe_description
    assert "src/main.c:42" in narrative.summary


def test_analyze_empty_findings():
    provider = LocalAIProvider()
    analysis = provider.analyze_findings([], _project())

    assert analysis.narratives == []
    assert "No candidate findings" in analysis.executive_summary


def test_analyze_prioritizes_high_severity():
    provider = LocalAIProvider()
    low = _make_finding(
        id="F-00001",
        severity=Severity.LOW,
        confidence=0.3,
        priority_score=1.0,
    )
    high = _make_finding(
        id="F-00002",
        title="Critical overflow",
        severity=Severity.CRITICAL,
        confidence=0.9,
        priority_score=9.5,
    )
    analysis = provider.analyze_findings([low, high], _project())

    priorities = " ".join(analysis.top_priorities)
    assert "F-00002" in priorities
    assert "manual review" in analysis.recommendations[0]


def test_narratives_have_no_grade_assertions():
    provider = LocalAIProvider()
    findings = [_make_finding()]
    analysis = provider.analyze_findings(findings, _project())
    narrative = analysis.narratives[0]

    assert narrative.validation_hint
    assert "before drawing conclusions" in narrative.validation_hint
