"""Configuration management for VRA."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from vra.core.exceptions import ConfigurationError


@dataclass
class AnalyzerConfig:
    clang_tidy: bool = True
    clang_analyzer: bool = True
    codeql: bool = True
    semgrep: bool = True
    cppcheck: bool = True
    flawfinder: bool = False
    sanitizer: bool = False


@dataclass
class RulesConfig:
    use_after_free: bool = True
    double_free: bool = True
    buffer_overflow: bool = True
    integer_overflow: bool = True
    memory_leak: bool = True
    null_deref: bool = True
    unchecked_return: bool = True
    resource_lifecycle: bool = True
    unchecked_length: bool = True
    unsafe_deserialization: bool = True
    untrusted_input: bool = True
    format_string: bool = True
    race_condition: bool = True
    toctou: bool = True
    command_injection: bool = True
    stack_recursion: bool = True
    sign_conversion: bool = True


@dataclass
class AIConfig:
    enabled: bool = False
    provider: str = "local"
    model: str = ""
    model_command: str = ""
    api_key: str = ""
    validate: bool = False
    devil_advocate: bool = True
    fp_threshold: float = 0.65
    validate_scope: str = "high"
    validate_limit: int = 200


@dataclass
class ValidationConfig:
    """Tuning for the rule-based FP-reduction stage.

    ``strict`` enables additional, probabilistic demotions: findings whose taint
    has no attacker-relevant root (or no provenance at all) are demoted as well,
    in addition to the provable signals that are always applied.
    """

    strict: bool = False


@dataclass
class VRAConfig:
    profile: str = "standard"
    analyzers: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    timeout: int = 300
    max_memory_mb: int = 2048
    parallel_analyzers: bool = True
    log_level: str = "INFO"


def load_config(config_path: Path | None = None) -> VRAConfig:
    if config_path is None:
        config_path = Path("vra.yaml")

    if not config_path.exists():
        return VRAConfig()

    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Failed to parse config: {e}")

    config = VRAConfig()

    if "analysis" in data:
        config.profile = data["analysis"].get("profile", config.profile)

    if "analyzers" in data:
        for key, value in data["analyzers"].items():
            if hasattr(config.analyzers, key):
                setattr(config.analyzers, key, value)

    if "rules" in data:
        for category, rules in data["rules"].items():
            if isinstance(rules, dict):
                for key, value in rules.items():
                    if hasattr(config.rules, key):
                        setattr(config.rules, key, value)

    if "ai" in data:
        for key, value in data["ai"].items():
            if hasattr(config.ai, key):
                setattr(config.ai, key, value)

    if "validation" in data:
        for key, value in data["validation"].items():
            if hasattr(config.validation, key):
                setattr(config.validation, key, value)

    return config
