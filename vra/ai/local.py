"""Local AI provider for VRA.

Two modes:

1. **Template mode (default).** A deterministic, rule-based natural-language
   generator that turns the aggregated findings into a coherent narrative.
   Fully functional offline with no external dependencies.

2. **Pluggable model mode.** If `model_command` (e.g. a llama.cpp / ollama
   invocation) is configured, the binary is invoked as a subprocess with the
   serialized findings and the free-text output is used. This is optional and
   degrades gracefully back to template mode on failure.
"""

from __future__ import annotations

import json
import shutil
import subprocess

from vra.ai.interface import AIAnalysis, AINarrative, AIProvider
from vra.core.enums import Severity
from vra.core.logging import get_logger
from vra.security.cwe import get_cwe_description

log = get_logger("ai.local")

SEVERITY_LABEL = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
}

DISCLAIMER = (
    "This analysis is generated automatically from static evidence and is "
    "intended to assist human review. Findings are candidate issues, not "
    "confirmed vulnerabilities. Manual validation is required before any "
    "action is taken."
)


class LocalAIProvider(AIProvider):
    provider_name = "local"

    def __init__(self, model: str = "", model_command: str = ""):
        self.model = model
        self.model_command = model_command.strip()

    def _call_model(self, text: str) -> str | None:
        if not self.model_command:
            return None
        binary = shutil.which(self.model_command.split()[0])
        if not binary:
            log.warning("Configured model command not found: %s", self.model_command)
            return None
        try:
            proc = subprocess.run(
                self.model_command.split(),
                input=text,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
        except Exception as e:  # noqa: BLE001
            log.warning("Local model invocation failed: %s", e)
        return None

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def analyze_findings(self, findings, project) -> AIAnalysis:
        _ = findings
        _ = project
        log.debug("Local AI analysis requested (model: %s)", self.model)
        return self._template_analysis(findings, project)

    def call_model(self, text: str) -> str | None:
        return self._call_model(text)

    # ------------------------------------------------------------------ #
    # Template-based generation
    # ------------------------------------------------------------------ #

    def _template_analysis(self, findings, project) -> AIAnalysis:
        findings = sorted(
            findings,
            key=lambda f: (f.priority_score, SEVERITY_LABEL.get(f.severity, "low")),
            reverse=True,
        )

        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            label = SEVERITY_LABEL.get(f.severity, "low")
            sev_counts[label] += 1

        dist = ", ".join(f"{sev}={sev_counts[sev]}" for sev in ("critical", "high", "medium", "low"))

        proj_name = project.name or "the target"
        if not findings:
            exec_summary = (
                f"No candidate findings were produced for {proj_name}. "
                "This may indicate clean code, limited analyzer coverage, or "
                "that issues exist beyond the current static-analysis scope."
            )
            return AIAnalysis(
                executive_summary=exec_summary,
                severity_distribution=dist,
                recommendations=[
                    "Confirm all relevant analyzers are installed and enabled.",
                    "Extend coverage with a memory-safety sanitizer build if available.",
                ],
                disclaimer=DISCLAIMER,
            )

        high_risk = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        high_risk_note = (
            f"{len(high_risk)} finding(s) at high/critical severity warrant immediate manual review."
            if high_risk
            else "No findings reached high or critical severity in this pass."
        )

        exec_summary = (
            f"The analysis of {proj_name} identified {len(findings)} candidate "
            f"finding(s) (severity distribution: {dist}). {high_risk_note} "
            "These are static-evidence candidates, not confirmed vulnerabilities, "
            "and require manual validation."
        )

        past = []
        for f in findings[:8]:
            loc = f"{f.source.file}:{f.source.line}"
            fn = f.source.function or "an unnamed function"
            sev = SEVERITY_LABEL.get(f.severity, "low")
            past.append(
                f"[{f.id}] {f.title} ({sev}/{f.confidence:.0%}/priority {f.priority_score:.1f}) at {loc} in {fn}"
            )

        top_priorities = [p for p in past] or ["No prioritized items."]

        narratives = [self._build_narrative(f) for f in findings]

        recommendations = []
        if high_risk:
            recommendations.append("Prioritize manual review of the high/critical findings listed above.")
        recommendations.append("Validate each finding in a debug build under ASan/UBSan where feasible.")
        recommendations.append("Trace reachability and input controllability before deducing exploitability.")
        recommendations.append("Record remediation once each finding is manually verified.")

        return AIAnalysis(
            executive_summary=exec_summary,
            severity_distribution=dist,
            top_priorities=top_priorities,
            narratives=narratives,
            recommendations=recommendations,
            disclaimer=DISCLAIMER,
        )

    def _build_narrative(self, f) -> AINarrative:
        cwe_desc = get_cwe_description(f.cwe)
        loc = f"{f.source.file}:{f.source.line}"
        fn = f.source.function or "an unnamed function"
        sev = SEVERITY_LABEL.get(f.severity, "low")

        tools = ", ".join(f.tools) if f.tools else "custom rule(s)"
        summary = (
            f"{f.title} was flagged with {sev} severity and {f.confidence:.0%} "
            f"confidence at {loc} (function {fn}). The issue maps to {f.cwe} "
            f"({cwe_desc}). Evidence was contributed by {tools}."
        )

        evidence_notes = ""
        if f.call_chain:
            chain = " -> ".join(e.function for e in f.call_chain)
            evidence_notes = f"A reachable call chain ({chain}) was identified from an entry point."
        elif f.source_snippet:
            evidence_notes = "A source snippet is available for review."

        val_hint = ""
        if f.reachability and f.controllability:
            val_hint = (
                f"Validation should confirm {f.reachability.value} reachability "
                f"and {f.controllability.value} input controllability before "
                "drawing conclusions."
            )

        fp_note = ""
        if f.false_positive_indicators:
            fp_note = "Note: " + "; ".join(f.false_positive_indicators)

        return AINarrative(
            finding_id=f.id,
            title=f.title,
            severity=sev,
            cwe=f.cwe,
            cwe_description=cwe_desc,
            location=loc,
            function=fn,
            summary=summary,
            evidence_notes=evidence_notes,
            validation_hint=val_hint,
            false_positive_note=fp_note,
        )

    # ------------------------------------------------------------------ #
    # Legacy interface (kept for back-compat)
    # ------------------------------------------------------------------ #

    def summarize_findings(self, findings_text: str) -> str:
        try:
            data = json.loads(findings_text)
        except (json.JSONDecodeError, TypeError):
            data = {}
        findings = []
        project = type("Proj", (), {"name": data.get("project_name", "")})()
        for item in data.get("findings", []):
            f = type(
                "F",
                (),
                {
                    "id": item.get("id", ""),
                    "title": item.get("title", ""),
                    "category": item.get("category", ""),
                    "cwe": item.get("cwe", "CWE-0"),
                    "severity": item.get("severity", "low"),
                    "confidence": item.get("confidence", 0.0),
                    "priority_score": item.get("priority_score", 0.0),
                    "source": type(
                        "S",
                        (),
                        {
                            "file": item.get("file", ""),
                            "line": item.get("line", 0),
                            "function": item.get("function", ""),
                        },
                    )(),
                    "tools": item.get("tools", []),
                    "call_chain": [],
                    "source_snippet": "",
                    "reachability": None,
                    "controllability": None,
                    "false_positive_indicators": [],
                },
            )()
            findings.append(f)
        analysis = self._template_analysis(findings, project)
        return analysis.executive_summary

    def generate_report_prose(self, context_text: str) -> str:
        analysis = self.analyze_findings([], None)
        return super().generate_report_prose(analysis)
