"""Rule registry for VRA."""

from __future__ import annotations

from vra.core.logging import get_logger
from vra.rules.base import SecurityRule

log = get_logger("rules.registry")


class RuleRegistry:
    _rules: dict[str, type[SecurityRule]] = {}

    @classmethod
    def register(cls, rule_cls: type[SecurityRule]) -> type[SecurityRule]:
        instance = rule_cls()
        cls._rules[instance.name] = rule_cls
        return rule_cls

    @classmethod
    def get(cls, name: str) -> type[SecurityRule] | None:
        return cls._rules.get(name)

    @classmethod
    def get_all(cls) -> list[SecurityRule]:
        return [rule_cls() for rule_cls in cls._rules.values()]

    @classmethod
    def get_by_category(cls, category: str) -> list[SecurityRule]:
        return [r for r in cls.get_all() if r.category == category]

    @classmethod
    def get_names(cls) -> list[str]:
        return list(cls._rules.keys())


def discover_rules() -> None:

    log.debug("Rules discovered")
