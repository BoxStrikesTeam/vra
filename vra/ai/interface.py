"""AI interface for VRA.

VRA's AI integration is an assistance layer. It produces natural-language
summaries, per-finding narratives, and prioritized guidance based on the
aggregated static evidence. It never asserts that a vulnerability is
"confirmed" purely from static data, and it never generates exploit or payload
code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from vra.core.logging import get_logger

log = get_logger("ai")


@dataclass
class AINarrative:
    finding_id: str
    title: str
    severity: str
    cwe: str
    cwe_description: str
    location: str
    function: str
    summary: str
    evidence_notes: str = ""
    validation_hint: str = ""
    false_positive_note: str = ""


@dataclass
class AIAnalysis:
    executive_summary: str = ""
    severity_distribution: str = ""
    top_priorities: list[str] = field(default_factory=list)
    narratives: list[AINarrative] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    disclaimer: str = ""


class AIProvider(ABC):
    provider_name: str = "generic"

    @abstractmethod
    def analyze_findings(self, findings, project) -> AIAnalysis:
        """Produce a structured natural-language analysis of findings."""

    def call_model(self, text: str) -> str | None:
        """Invoke the backing model with raw text and return its output.

        Used by the AI validation passes (verifier + devil's advocate).
        Providers that cannot do free-text inference return ``None``.
        """
        return None

    def summarize_findings(self, findings, project) -> str:
        analysis = self.analyze_findings(findings, project)
        return analysis.executive_summary

    def generate_report_prose(self, analysis: AIAnalysis) -> str:
        parts = [analysis.executive_summary]
        if analysis.top_priorities:
            parts.append("Priorities:\n" + "\n".join(f"- {p}" for p in analysis.top_priorities))
        if analysis.recommendations:
            parts.append("Recommendations:\n" + "\n".join(f"- {r}" for r in analysis.recommendations))
        parts.append(analysis.disclaimer)
        return "\n\n".join(p for p in parts if p)


class NoAIProvider(AIProvider):
    provider_name = "disabled"

    def analyze_findings(self, findings, project) -> AIAnalysis:
        return AIAnalysis(
            executive_summary="AI-assisted analysis is disabled.",
            disclaimer="Enable AI integration via configuration to receive automated narrative summaries.",
        )
