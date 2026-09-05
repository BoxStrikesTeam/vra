"""Unit tests for finding fingerprinting."""

from vra.core.enums import Severity
from vra.core.models import Finding, SourceLocation
from vra.correlation.fingerprint import compute_fingerprint


def _make_finding(file="src/parser.c", line=481, function="parse_attribute", cwe="CWE-787", title="OOB write"):
    return Finding(
        id="",
        title=title,
        category="memory",
        cwe=cwe,
        severity=Severity.HIGH,
        confidence=0.5,
        source=SourceLocation(file=file, line=line, function=function),
    )


def test_fingerprint_deterministic():
    f1 = _make_finding()
    f2 = _make_finding()
    assert compute_fingerprint(f1) == compute_fingerprint(f2)


def test_fingerprint_differs_for_different_location():
    f1 = _make_finding(line=481)
    f2 = _make_finding(line=482)
    assert compute_fingerprint(f1) != compute_fingerprint(f2)


def test_fingerprint_differs_for_different_cwe():
    f1 = _make_finding(cwe="CWE-787")
    f2 = _make_finding(cwe="CWE-120")
    assert compute_fingerprint(f1) != compute_fingerprint(f2)


def test_fingerprint_hex_format():
    fp = compute_fingerprint(_make_finding())
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)
