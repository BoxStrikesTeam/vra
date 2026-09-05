"""Unit tests for the AI purpose (prompt) catalog."""

from __future__ import annotations

import pytest

from vra.ai.interface import AIAnalysis, AIProvider
from vra.ai.prompts import (
    KIND_ADVOCATE,
    KIND_PROSE,
    KIND_SUMMARY,
    KIND_VERIFY,
    get_preset,
    list_presets,
    run_purpose,
)

_FAKE_PROJECT = type("Project", (), {"name": "zeek"})()


class _FakeProvider(AIProvider):
    def __init__(self, prose: str | None = "model answer"):
        self._prose = prose
        self.called_with: list[str] = []

    def analyze_findings(self, findings, project) -> AIAnalysis:
        self.called_with.append("analyze_findings")
        return AIAnalysis(executive_summary="template summary")

    def call_model(self, text: str) -> str | None:
        self.called_with.append(text)
        return self._prose


def test_catalog_is_well_formed():
    presets = list_presets()
    assert presets
    keys = [p.key for p in presets]
    assert len(keys) == len(set(keys)), "preset keys must be unique"
    for p in presets:
        assert p.template.count("{context}") == 1, f"{p.key}: missing {{context}} placeholder"
        assert p.kind in (KIND_SUMMARY, KIND_VERIFY, KIND_ADVOCATE, KIND_PROSE)
        assert p.name and p.description


def test_default_purpose_is_summary():
    assert get_preset("summary").kind == KIND_SUMMARY


def test_get_preset_lookup_and_errors():
    assert get_preset("reMediation").key == "remediation"
    with pytest.raises(ValueError):
        get_preset("does-not-exist")
    with pytest.raises(ValueError):
        get_preset("")


def test_render_only_replaces_context_placeholder():
    preset = get_preset("report")
    rendered = preset.render("FINDING-JSON")
    assert "FINDING-JSON" in rendered
    assert "{context}" not in rendered
    assert "{project" not in rendered  # no other named placeholders


def test_run_purpose_summary_delegates_to_analysis():
    provider = _FakeProvider()
    out = run_purpose(provider, "summary", [], None)
    assert out is not None
    assert out.executive_summary == "template summary"
    assert provider.called_with == ["analyze_findings"]


@pytest.mark.parametrize("purpose", ["triage", "advocate"])
def test_run_purpose_structured_passes_return_none(purpose):
    provider = _FakeProvider()
    assert run_purpose(provider, purpose, None, None) is None


def test_run_purpose_prose_uses_model_output():
    provider = _FakeProvider(prose="Fix it with strlcpy.")
    out = run_purpose(provider, "remediation", [], _FAKE_PROJECT)
    assert out is not None
    assert "Fix it with strlcpy." in out.executive_summary
    assert provider.called_with and "analyze_findings" not in provider.called_with


def test_run_purpose_prose_fails_open_to_none():
    provider = _FakeProvider(prose=None)
    assert run_purpose(provider, "explain", [], _FAKE_PROJECT) is None


def test_all_purposes_resolve():
    for p in list_presets():
        assert get_preset(p.key) is p
