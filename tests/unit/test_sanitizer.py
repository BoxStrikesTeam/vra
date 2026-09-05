"""Unit tests for the sanitizer analyzer parse logic."""

from __future__ import annotations

from vra.analyzers.sanitizer import SANITIZER_FLAGS, SanitizerAnalyzer

UAF_OUTPUT = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x6020000004f0 at pc 0x000000
READ of size 1 at 0x6020000004f0 thread T0
    #0 0x55aa 0x55aa in process_msg /vra/main.c:12
    #1 0x55bb 0x55bb in main /vra/main.c:20
0x6020000004f0 is located 0 bytes inside of 32-byte region
SUMMARY: AddressSanitizer: heap-use-after-free /vra/main.c:12
"""

BO_OUTPUT = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000005f0
    #0 0x11 in memcpy /a.c:5
SUMMARY: AddressSanitizer: heap-buffer-overflow /a.c:5
"""

CLEAN_OUTPUT = """\
Process exited with code 0
"""


def test_parse_detects_use_after_free():
    findings = SanitizerAnalyzer("address").parse(UAF_OUTPUT)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == "CWE-416"
    assert f.severity.value == "high"
    assert f.confidence > 0.9


def test_parse_detects_buffer_overflow():
    findings = SanitizerAnalyzer("address").parse(BO_OUTPUT)
    assert any(f.cwe == "CWE-787" for f in findings)


def test_parse_clean_output_no_findings():
    findings = SanitizerAnalyzer("address").parse(CLEAN_OUTPUT)
    assert findings == []


def test_available_requires_compiler():
    analyzer = SanitizerAnalyzer("address")
    # In a normal build environment a compiler should be present, but the
    # method should never raise and must return a bool.
    result = analyzer.available()
    assert isinstance(result, bool)


def test_sanitizer_flags_mapping():
    addr = SANITIZER_FLAGS["address"]
    assert "-fsanitize=address" in addr
    undef = SANITIZER_FLAGS["undefined"]
    assert "-fsanitize=undefined" in undef
