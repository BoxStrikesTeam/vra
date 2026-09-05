"""AI Pass-2 validation: the devil's advocate.

A second model (or a second invocation) is asked to *disprove* each finding that
survived Pass-1. It must argue why the candidate could still be a false
positive. Findings that the advocate cannot meaningfully attack are treated as
``survives``; findings the advocate successfully challenges are demoted.

Like Pass-1 this is strict fail-open: unparseable or absent model output never
drops or weakens a finding.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from vra.ai.validator import _serialize_finding
from vra.core.logging import get_logger

log = get_logger("ai.devil_advocate")

VERDICT_SURVIVES = "survives"
VERDICT_CONFIRMED_FP = "confirmed_fp"
VERDICT_CHALLENGED = "challenged"

_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)


@dataclass
class AIDevilAdvocateVerdict:
    finding_id: str
    verdict: str = VERDICT_SURVIVES
    reason: str = ""


def build_challenge_prompt(findings: list, project) -> str:
    proj = getattr(project, "name", None) or "the target"
    items = [json.dumps(_serialize_finding(f), ensure_ascii=False) for f in findings]
    return (
        "You are a skeptical security researcher reviewing the static-analysis "
        f"findings for the C/C++ project '{proj}'. Your task is to DISPROVE each "
        "finding as a false positive. For each candidate, find the strongest reason "
        "it may not be a real vulnerability (mitigating guard, wrong root cause, "
        "unreachable path, unchecked cast, input already bounded, safe API variant, "
        "etc.). If you genuinely cannot find a plausible counter-argument, verdict "
        "is 'survives'.\n\n"
        "Respond with one JSON object per finding, in the same order, each with keys "
        "\"id\", \"verdict\" (\"confirmed_fp\" | \"challenged\" | \"survives\") and "
        "\"reason\" (one short sentence describing the strongest counter-argument).\n\n"
        "FINDINGS:\n" + "\n---\n".join(items)
    )


def _loose_load(text: str) -> list | None:
    try:
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end > start:
            return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        pass
    return None


def parse_challenges(text: str) -> list[AIDevilAdvocateVerdict] | None:
    if not text:
        return None
    m = _JSON_FENCE_RE.match(text.strip())
    if m:
        text = m.group(1)
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        data = _loose_load(text) if isinstance(text, str) else None
    if data is None:
        return None
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return None
    results = []
    for item in data:
        if not isinstance(item, dict):
            continue
        verdict = item.get("verdict", VERDICT_SURVIVES)
        if verdict not in (VERDICT_SURVIVES, VERDICT_CONFIRMED_FP, VERDICT_CHALLENGED):
            verdict = VERDICT_SURVIVES
        results.append(
            AIDevilAdvocateVerdict(
                finding_id=str(item.get("id", "")),
                verdict=verdict,
                reason=str(item.get("reason", "")),
            )
        )
    return results


def challenge_findings(provider, findings: list, project) -> dict[str, AIDevilAdvocateVerdict]:
    """Run Pass-2 on ``findings``. Returns {finding_id: verdict}. Fail-open."""
    if not findings:
        return {}
    try:
        raw = provider.call_model(build_challenge_prompt(findings, project))
    except Exception as e:  # noqa: BLE001
        log.warning("AI devil's-advocate pass failed: %s", e)
        return {}
    if not raw:
        log.debug("AI devil's-advocate pass returned no model output")
        return {}
    verdicts = parse_challenges(raw)
    if not verdicts:
        log.warning("AI devil's-advocate output could not be parsed; findings untouched")
        return {}
    return {v.finding_id: v for v in verdicts if v.finding_id}
