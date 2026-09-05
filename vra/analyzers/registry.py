"""Analyzer plugin registry for VRA."""

from __future__ import annotations

from vra.analyzers.base import Analyzer
from vra.core.logging import get_logger

log = get_logger("analyzers.registry")


class AnalyzerRegistry:
    _analyzers: dict[str, type[Analyzer]] = {}

    @classmethod
    def register(cls, analyzer_cls: type[Analyzer]) -> type[Analyzer]:
        instance = analyzer_cls()
        cls._analyzers[instance.name] = analyzer_cls
        log.debug("Registered analyzer: %s", instance.name)
        return analyzer_cls

    @classmethod
    def get(cls, name: str) -> type[Analyzer] | None:
        return cls._analyzers.get(name)

    @classmethod
    def get_available(cls) -> list[Analyzer]:
        available = []
        for name, analyzer_cls in cls._analyzers.items():
            instance = analyzer_cls()
            if instance.available():
                available.append(instance)
            else:
                log.info("Analyzer '%s' is not available", name)
        return available

    @classmethod
    def get_all(cls) -> list[Analyzer]:
        return [analyzer_cls() for analyzer_cls in cls._analyzers.values()]

    @classmethod
    def get_names(cls) -> list[str]:
        return list(cls._analyzers.keys())


def discover_analyzers() -> None:

    log.debug("Analyzers discovered")
