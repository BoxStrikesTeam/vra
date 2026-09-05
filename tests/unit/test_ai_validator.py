"""Unit tests for the AI validation passes (verifier + devil's advocate)."""

from __future__ import annotations

import json
import types

from vra.ai.devil_advocate import (
    challenge_findings,
    parse_challenges,
)
from vra.ai.validator import (
    build_verification_prompt,
    parse_verifications,
    verify_findings,
)
from vra.core.enums import Severity


class _FakeProvider:
    provider_name = "fake"
    model_command = "fake"

    def __init__(self, output: str | None):
        self.output = output

    def call_model(self, text: str) -> str | None:
        return self.output


def _finding(fid: str = "F-00001") -> types.SimpleNamespace:
    return types.SimpleNamespace(
        id=fid,
        title="Use after free",
        category="memory",
        cwe="CWE-416",
        severity=Severity.HIGH,
        confidence=0.8,
        priority_score=8.0,
        source=types.SimpleNamespace(file="/proj/a.c", line=10, function="run"),
        tools=["clang"],
        reachability=types.SimpleNamespace(value="high"),
        controllability=types.SimpleNamespace(value="medium"),
        attack_surface="network",
        dataflow=[],
        call_chain=[],
        source_snippet="free(p); use(p);",
    )


def test_parse_verifications_handles_list():
    text = json.dumps(
        [
            {"id": "F-00001", "verdict": "confirmed", "confidence_override": 0.9, "reason": "clear use after free"},
            {"id": "F-00002", "verdict": "false_positive", "confidence_override": None, "reason": "likely bounded"},
        ]
    )
    result = parse_verifications(text)
    assert result is not None
    assert len(result) == 2
    assert result[0].verdict == "confirmed"
    assert result[0].confidence_override == 0.9
    assert result[1].verdict == "false_positive"


def test_verify_findings_maps_ids():
    output = json.dumps(
        [{"id": "F-00001", "verdict": "suspicious", "confidence_override": None, "reason": "need review"}]
    )
    provider = _FakeProvider(output)
    result = verify_findings(provider, [_finding()], _project())
    assert "F-00001" in result
    assert result["F-00001"].verdict == "suspicious"


def test_verify_findings_fail_open_on_bad_output():
    provider = _FakeProvider("completely not json")
    result = verify_findings(provider, [_finding("F-00009")], _project())
    assert result == {}


def test_verify_findings_fail_open_on_none():
    result = verify_findings(_FakeProvider(None), [_finding()], _project())
    assert result == {}


def test_build_prompt_contains_finding_id():
    prompt = build_verification_prompt([_finding("F-00001")], _project())
    assert "F-00001" in prompt


def test_parse_challenges_handles_survives():
    text = json.dumps([{"id": "F-00001", "verdict": "survives", "reason": "no counter-argument"}])
    result = parse_challenges(text)
    assert result is not None
    assert result[0].verdict == "survives"


def test_challenge_findings_confirmed_fp():
    output = json.dumps([{"id": "F-00001", "verdict": "confirmed_fp", "reason": "ptr is set to NULL"}])
    result = challenge_findings(_FakeProvider(output), [_finding()], _project())
    assert result["F-00001"].verdict == "confirmed_fp"


def _project():
    return types.SimpleNamespace(name="test-proj")
