"""AI Pass-1 validation: per-finding verifier.

For each candidate finding the model is asked to decide, purely from the static
evidence bundled in the prompt, whether the issue is ``confirmed``, requires
human review (``suspicious``) or looks like a ``false_positive``. Only
findings that the model can call a model on are annotated; anything that cannot
be parsed or that never answers is left untouched (fail-open so a broken model
never silently drops real findings).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from vra.core.logging import get_logger

log = get_logger("ai.validator")

VERDICT_CONFIRMED = "confirmed"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_FALSE_POSITIVE = "false_positive"

_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)


@dataclass
class AIVerificationVerdict:
    finding_id: str
    verdict: str = VERDICT_SUSPICIOUS
    confidence_override: float | None = None
    reason: str = ""


def _loc(value) -> str:
    if value is None:
        return ""
    return getattr(value, "value", None) or str(value)


def _serialize_finding(f) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "category": f.category,
        "cwe": f.cwe,
        "severity": _loc(getattr(f, "severity", None)),
        "confidence": getattr(f, "confidence", 0.0),
        "priority_score": getattr(f, "priority_score", 0.0),
        "file": getattr(getattr(f, "source", None), "file", ""),
        "line": getattr(getattr(f, "source", None), "line", 0),
        "function": getattr(getattr(f, "source", None), "function", ""),
        "tools": getattr(f, "tools", []),
        "reachability": _loc(getattr(getattr(f, "reachability", None), "value", None)),
        "controllability": _loc(getattr(getattr(f, "controllability", None), "value", None)),
        "attack_surface": getattr(f, "attack_surface", ""),
        "dataflow": [
            s.__dict__ if hasattr(s, "__dict__") else str(s)
            for s in getattr(f, "dataflow", [])
        ],
        "call_chain": [
            c.__dict__ if hasattr(c, "__dict__") else str(c)
            for c in getattr(f, "call_chain", [])
        ],
        "source_snippet": getattr(f, "source_snippet", "")[:500],
    }


def build_verification_prompt(findings: list, project) -> str:
    """Build a single prompt carrying every finding to verify."""
    proj = getattr(project, "name", None) or "the target"
    items = [json.dumps(_serialize_finding(f), ensure_ascii=False) for f in findings]
    return (
        "You are a vulnerability-validation assistant for a static analyzer on the "
        f"C/C++ project '{proj}'. Each item below is a *candidate* finding backed by "
        "static evidence only. For every item decide whether the evidence supports a "
        "real vulnerability, only looks suspicious, or is likely a false positive. "
        "Be conservative: never claim more than the data shows; when in doubt answer "
        "'suspicious'.\n\n"
        "Respond with one JSON object per finding, in the same order, each with keys "
        "\"id\", \"verdict\" (one of \"confirmed\" | \"suspicious\" | \"false_positive\"), "
        "\"confidence_override\" (0.0-1.0 or null) and \"reason\" (one short sentence).\n\n"
        "FINDINGS:\n" + "\n---\n".join(items)
    )


def parse_verifications(text: str) -> list[AIVerificationVerdict] | None:
    if not text:
        return None
    m = _JSON_FENCE_RE.match(text.strip())
    if m:
        text = m.group(1)
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        # Tolerate a top-level list or a single object.
        if isinstance(text, str):
            data = _loose_load(text)
        else:
            return None
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
        finding_id = item.get("id", "")
        verdict = item.get("verdict", VERDICT_SUSPICIOUS)
        if verdict not in (VERDICT_CONFIRMED, VERDICT_SUSPICIOUS, VERDICT_FALSE_POSITIVE):
            verdict = VERDICT_SUSPICIOUS
        conf = item.get("confidence_override")
        results.append(
            AIVerificationVerdict(
                finding_id=finding_id,
                verdict=verdict,
                confidence_override=conf if isinstance(conf, (int, float)) else None,
                reason=str(item.get("reason", "")),
            )
        )
    return results


def _loose_load(text: str) -> list | None:
    """Recover JSON from a response that is not strictly parseable."""
    try:
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end > start:
            return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        pass
    return None


def verify_findings(provider, findings: list, project) -> dict[str, AIVerificationVerdict]:
    """Run Pass-1 on ``findings``. Returns {finding_id: verdict}. Fail-open."""
    if not findings:
        return {}
    try:
        prompt = build_verification_prompt(findings, project)
        raw = provider.call_model(prompt)
    except Exception as e:  # noqa: BLE001
        log.warning("AI verification pass failed: %s", e)
        return {}
    if not raw:
        log.debug("AI verification pass returned no model output")
        return {}
    verdicts = parse_verifications(raw)
    if not verdicts:
        log.warning("AI verification output could not be parsed; findings untouched")
        return {}
    return {v.finding_id: v for v in verdicts if v.finding_id}
