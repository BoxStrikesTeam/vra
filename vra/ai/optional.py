"""Optional AI integration for VRA."""

from __future__ import annotations

import json

from vra.ai.interface import AIAnalysis, AIProvider, NoAIProvider
from vra.ai.local import LocalAIProvider
from vra.core.config import AIConfig
from vra.core.logging import get_logger

log = get_logger("ai.optional")


def _severity_label(f) -> str:
    sev = getattr(f, "severity", None)
    if sev is None:
        return "low"
    return getattr(sev, "value", None) or str(sev).lower()


def serialize_findings(findings, project) -> str:
    """Serialize findings into a JSON payload suitable for an LLM provider."""
    items = []
    for f in findings:
        items.append(
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "cwe": f.cwe,
                "severity": _severity_label(f),
                "confidence": f.confidence,
                "priority_score": f.priority_score,
                "file": f.source.file,
                "line": f.source.line,
                "function": f.source.function,
                "tools": f.tools,
                "reachability": getattr(f.reachability, "value", None),
                "controllability": getattr(f.controllability, "value", None),
            }
        )
    return json.dumps(
        {
            "project_name": project.name if project else "",
            "findings": items,
        },
        indent=2,
    )


def create_ai_provider(config: AIConfig) -> AIProvider:
    if not config.enabled:
        return NoAIProvider()

    if config.provider == "local":
        return LocalAIProvider(model=config.model, model_command=config.model_command)

    log.warning("Unknown AI provider: %s, using NoAIProvider", config.provider)
    return NoAIProvider()


def run_ai_analysis(provider: AIProvider, findings, project) -> AIAnalysis:
    """Run provider analysis, falling back to a harmless empty analysis."""
    try:
        return provider.analyze_findings(findings, project)
    except Exception as e:  # noqa: BLE001
        log.warning("AI analysis failed, returning empty: %s", e)
        return AIAnalysis(executive_summary="", disclaimer="")
