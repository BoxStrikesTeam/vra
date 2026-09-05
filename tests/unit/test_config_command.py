"""Unit tests for the `vra config` CLI command group."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
import yaml

from vra.cli.config_command import VRA_CONFIG_TEMPLATE, _coerce, config_init, config_set, config_unset
from vra.core.config import load_config


def test_coerce_types():
    assert _coerce("true") is True
    assert _coerce("FALSE") is False
    assert _coerce("500") == 500
    assert _coerce("0.65") == 0.65
    assert _coerce("hello world") == "hello world"
    assert _coerce("null") is None


def test_config_set_roundtrips_into_load_config(tmp_path: Path):
    target = tmp_path / "vra.yaml"
    config_set("ai.model_command", "ollama run llama3.1", path=str(target))
    config_set("ai.validate", "true", path=str(target))
    config_set("ai.validate_limit", "500", path=str(target))

    cfg = load_config(target)
    assert cfg.ai.model_command == "ollama run llama3.1"
    assert cfg.ai.validate is True
    assert cfg.ai.validate_limit == 500


def test_config_unset_removes_key(tmp_path: Path):
    target = tmp_path / "vra.yaml"
    config_set("ai.api_key", "secret", path=str(target))
    config_unset("ai.api_key", path=str(target))
    data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    assert "api_key" not in data.get("ai", {})


def test_config_init_template_documents_ai(tmp_path: Path):
    target = tmp_path / "vra.yaml"
    config_init(path=str(target))
    assert target.exists()
    text = target.read_text(encoding="utf-8")
    assert "model_command" in text
    assert "validate: false" in text
    assert "devil_advocate: true" in text


def test_config_init_refuses_overwrite(tmp_path: Path):
    target = tmp_path / "vra.yaml"
    target.write_text("existing", encoding="utf-8")
    with pytest.raises(typer.Exit):
        config_init(force=False, path=str(target))
    assert target.read_text(encoding="utf-8") == "existing"


def test_config_init_force_overwrites(tmp_path: Path):
    target = tmp_path / "vra.yaml"
    target.write_text("existing", encoding="utf-8")
    config_init(force=True, path=str(target))
    assert target.read_text(encoding="utf-8").startswith("# VRA configuration")


def test_template_is_valid_yaml():
    data = yaml.safe_load(VRA_CONFIG_TEMPLATE)
    assert data["ai"]["provider"] == "local"
    assert data["ai"]["validate"] is False
