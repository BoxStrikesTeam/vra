"""Rule engine base and ABC for VRA."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vra.core.logging import get_logger
from vra.core.models import Finding, RuleContext

log = get_logger("rules")


class SecurityRule(ABC):
    name: str = "base"
    category: str = "general"
    cwe: str = "CWE-0"
    description: str = ""

    @abstractmethod
    def analyze(self, context: RuleContext) -> list[Finding]: ...

    def _make_finding(
        self,
        title: str,
        severity: str,
        confidence: float,
        file: str,
        line: int,
        function: str = "",
    ) -> Finding:
        from vra.core.models import SourceLocation

        return Finding(
            id="",
            title=title,
            category=self.category,
            cwe=self.cwe,
            severity=severity,
            confidence=confidence,
            source=SourceLocation(file=file, line=line, function=function),
            tools=[f"rule:{self.name}"],
        )
