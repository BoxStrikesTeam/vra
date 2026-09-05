"""Unit tests for finding deduplication."""

from vra.core.enums import Severity
from vra.core.models import Finding, SourceLocation
from vra.correlation.deduplicator import deduplicate_findings


def _make_finding(tool, line=100, title="Same issue", cwe="CWE-120"):
    return Finding(
        id="",
        title=title,
        category="memory",
        cwe=cwe,
        severity=Severity.HIGH,
        confidence=0.5,
        source=SourceLocation(file="main.c", line=line, function="main"),
        tools=[tool],
    )


def test_deduplicates_same_finding():
    findings = [
        _make_finding("codeql"),
        _make_finding("clang"),
        _make_finding("semgrep"),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 1
    assert len(result[0].tools) == 3


def test_keeps_different_findings():
    findings = [
        _make_finding("codeql", line=100, title="A"),
        _make_finding("clang", line=200, title="B"),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 2


def test_confidence_boosted_for_multiple_sources():
    f1 = _make_finding("codeql")
    f2 = _make_finding("clang")
    result = deduplicate_findings([f1, f2])
    assert result[0].confidence > 0.5
