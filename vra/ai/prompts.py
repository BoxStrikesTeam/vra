"""AI purpose presets: the prompt catalog users can pick from.

When AI is enabled, a run chooses one *purpose* that steers how the model is
asked to help: triage findings, argue against them, write remediation or a
technical report, explain them, or produce a threat recap. The catalog is
inspectable with ``vra ai list`` / ``vra ai show <key>`` and is selected with
``ai.purpose`` in ``vra.yaml`` (or ``--ai-purpose`` on the analyze command).

Kinds:

* ``summary``  - default narrative analysis (executive summary, priorities...).
* ``verify``   - per-finding TP/FP verdict (``confirmed``/``suspicious``/``false_positive``).
* ``advocate`` - second pass that tries to disprove surviving findings.
* ``prose``    - free-text guidance/report written by the model.

The ``verify``/``advocate`` kinds are delegated to the structured AI validation
passes (``vra.ai.validator`` / ``vra.ai.devil_advocate``) and only run when the
model command is reachable; selecting them turns on ``ai.validate``.
Prose/summary runs always fall back to the deterministic template analysis when
no model is available (fail-open: a broken model never empties a report).
"""

from __future__ import annotations

from dataclasses import dataclass

from vra.ai.interface import AIAnalysis
from vra.ai.local import DISCLAIMER
from vra.core.logging import get_logger

log = get_logger("ai.prompts")

KIND_SUMMARY = "summary"
KIND_VERIFY = "verify"
KIND_ADVOCATE = "advocate"
KIND_PROSE = "prose"

_CONTEXT_PLACEHOLDER = "{context}"


@dataclass(frozen=True)
class PromptPreset:
    key: str
    name: str
    description: str
    kind: str
    template: str

    def render(self, context: str) -> str:
        return self.template.replace(_CONTEXT_PLACEHOLDER, context)


PROMPT_PRESETS: list[PromptPreset] = [
    PromptPreset(
        key="summary",
        name="Executive summary",
        description=(
            "Risk overview of the project: finding count, severity distribution, "
            "top priorities and a per-finding narrative. This is the default when "
            "AI is enabled."
        ),
        kind=KIND_SUMMARY,
        template=(
            "You are a vulnerability-research assistant working with static-analysis "
            "evidence for a C/C++ project. Produce a concise executive summary: "
            "overall risk posture, severity distribution, the top 3-5 priorities "
            "with reasoning, and anything that stands out as anomalous. "
            "Do not claim more than the evidence shows.\n\n"
            "CONTEXT:\n{context}"
        ),
    ),
    PromptPreset(
        key="triage",
        name="TP/FP triage",
        description=(
            "Have the model decide, per finding, whether the static evidence "
            "supports a real issue (confirmed), needs review (suspicious) or is "
            "likely a false positive. Same pass as ai.validate."
        ),
        kind=KIND_VERIFY,
        template=(
            "You are a vulnerability-validation assistant. For every candidate "
            "finding decide, strictly from the bundled static evidence, whether it "
            "is confirmed, suspicious, or a false positive. Be conservative: in "
            "doubt, answer suspicious. Never claim more than the data shows.\n\n"
            "CONTEXT:\n{context}"
        ),
    ),
    PromptPreset(
        key="advocate",
        name="Devil's advocate",
        description=(
            "Second validation pass: the model tries to DISPROVE each finding that "
            "survived triage. Findings it cannot meaningfully attack are kept."
        ),
        kind=KIND_ADVOCATE,
        template=(
            "You are a skeptical security researcher. For each surviving finding "
            "find the strongest reason it may be a false positive: mitigating "
            "guard, unreachable path, bounded input, wrong root cause, safe API "
            "variant. If no plausible counter-argument exists, the finding "
            "survives.\n\n"
            "CONTEXT:\n{context}"
        ),
    ),
    PromptPreset(
        key="remediation",
        name="Remediation guidance",
        description=(
            "Actionable fix advice per finding: safer API, bounds/validation "
            "pattern, resource handling - tuned to the flagged line and CWE."
        ),
        kind=KIND_PROSE,
        template=(
            "You are a security engineering advisor. For each flagged location give "
            "concrete, copy-editable remediation: the safe API or pattern to use, "
            "where the guard/validation belongs, and what the fix removes. "
            "Do not write exploits or payload code - only defensive fixes.\n\n"
            "CONTEXT:\n{context}"
        ),
    ),
    PromptPreset(
        key="report",
        name="Technical report",
        description=(
            "A formal written technical report on the findings, suitable as the "
            "narrative prose of the deliverable documentation."
        ),
        kind=KIND_PROSE,
        template=(
            "You are a technical writer producing a security assessment report. "
            "Write formal prose covering: scope and method, the finding inventory "
            "with severities, the most important issues in depth, and recommended "
            "next steps. Keep claims grounded in the static evidence.\n\n"
            "CONTEXT:\n{context}"
        ),
    ),
    PromptPreset(
        key="threat",
        name="Threat recap",
        description=(
            "Rank findings by exploitability and reachability for the security "
            "team: which issues an attacker could realistically reach and abuse."
        ),
        kind=KIND_PROSE,
        template=(
            "You are a threat modeler. Using the reachability, controllability and "
            "call-chain evidence, rank the findings by how an attacker could "
            "realistically reach and exploit them. Separate 'reachable and "
            "attacker-controlled', 'reachable but not proven', and 'low risk'. "
            "Avoid over-claiming.\n\n"
            "CONTEXT:\n{context}"
        ),
    ),
    PromptPreset(
        key="explain",
        name="Learning walkthrough",
        description=(
            "Educate a human reviewer: why each finding was flagged, what the CWE "
            "means, and how the pattern can be triggered - no exploit code."
        ),
        kind=KIND_PROSE,
        template=(
            "You are a mentor explaining static-analysis findings to a reviewer. "
            "For each item explain: what the pattern is, why automated analysis "
            "flagged it here, what the CWE class means, and the simplest legitimate "
            "trigger. Use plain language, no exploit or payload code.\n\n"
            "CONTEXT:\n{context}"
        ),
    ),
]

_PRESET_BY_KEY = {p.key: p for p in PROMPT_PRESETS}


def list_presets() -> list[PromptPreset]:
    """Return every prompt preset in catalog order."""
    return list(PROMPT_PRESETS)


def get_preset(key: str) -> PromptPreset:
    """Look up a preset by key (case-insensitive)."""
    preset = _PRESET_BY_KEY.get((key or "").strip().lower())
    if preset is None:
        raise ValueError(
            f"Unknown AI purpose: {key or ''!r}. "
            f"Available: {', '.join(_PRESET_BY_KEY)}"
        )
    return preset


def run_purpose(provider, purpose: str, findings, project) -> AIAnalysis | None:
    """Run a purpose against ``provider``.

    Returns ``None`` when the purpose is a structured validation pass (those are
    handled by the AI validation pipeline) or when no model output is available
    (fail-open: the caller should fall back to the template analysis).
    """
    preset = get_preset(purpose)
    if preset.kind in (KIND_VERIFY, KIND_ADVOCATE):
        return None
    if preset.kind == KIND_SUMMARY:
        return provider.analyze_findings(findings, project)

    from vra.ai.optional import serialize_findings

    context = serialize_findings(findings, project)
    try:
        text = provider.call_model(preset.render(context))
    except Exception as e:  # noqa: BLE001
        log.warning("AI purpose '%s' failed: %s", preset.key, e)
        text = None
    if not text:
        log.debug("AI purpose '%s' produced no model output", preset.key)
        return None
    return AIAnalysis(
        executive_summary=f"[{preset.name}]\n{text}",
        top_priorities=[f"{preset.name}: {preset.description}"],
        disclaimer=DISCLAIMER,
    )
