"""Unit tests for analyzer output parsing."""

from vra.analyzers.cppcheck import CppcheckAnalyzer
from vra.analyzers.flawfinder import FlawfinderAnalyzer
from vra.analyzers.semgrep import SemgrepAnalyzer


def test_cppcheck_xml_parse():
    xml_output = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <error id="memleak" severity="error" msg="Memory leak: variable" verbose="Memory leak: variable">
    <location file="src/foo.c" line="42" column="5"/>
  </error>
</results>
"""
    analyzer = CppcheckAnalyzer()
    findings = analyzer.parse(xml_output)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-401"
    assert findings[0].source.file == "src/foo.c"
    assert findings[0].source.line == 42


def test_semgrep_json_parse():
    json_output = """{"results": [
        {
            "check_id": "c.lang.security.memcpy",
            "path": "src/buf.c",
            "start": {"line": 10},
            "extra": {"message": "Unsafe memcpy", "severity": "ERROR", "metadata": {"cwe": ["CWE-120"]}}
        }
    ]}
"""
    analyzer = SemgrepAnalyzer()
    findings = analyzer.parse(json_output)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-120"
    assert findings[0].severity.value == "high"


def test_flawfinder_json_parse():
    json_output = """[{"fname": "main.c", "line": 15, "name": "strcpy", "level": 4, "cwe": "CWE-120", "context": "strcpy(dst, src)"}]"""  # noqa: E501
    analyzer = FlawfinderAnalyzer()
    findings = analyzer.parse(json_output)
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
