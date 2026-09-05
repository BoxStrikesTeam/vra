"""Unit tests for adaptive analyzer timeout scaling."""

from __future__ import annotations

from types import SimpleNamespace

from vra.analyzers.base import Analyzer


class _FakeAnalyzer(Analyzer):
    name = "fake"

    def prepare(self, context) -> None:  # noqa: D102
        pass

    def run(self, context):  # noqa: D102
        pass

    def parse(self, raw_result: str):  # noqa: D102
        return []


def test_timeout_small_project_uses_default():
    ctx = SimpleNamespace(project=SimpleNamespace(total_files=100))
    assert _FakeAnalyzer()._timeout_for(ctx, 600) == 600


def test_timeout_medium_project_scaled():
    ctx = SimpleNamespace(project=SimpleNamespace(total_files=2000))
    assert _FakeAnalyzer()._timeout_for(ctx, 600) == 300


def test_timeout_large_project_capped():
    ctx = SimpleNamespace(project=SimpleNamespace(total_files=8000))
    assert _FakeAnalyzer()._timeout_for(ctx, 600) == 180


def test_timeout_never_exceeds_default():
    ctx = SimpleNamespace(project=SimpleNamespace(total_files=8000))
    assert _FakeAnalyzer()._timeout_for(ctx, 120) == 120


def test_timeout_missing_project_uses_default():
    assert _FakeAnalyzer()._timeout_for(SimpleNamespace(), 300) == 300
