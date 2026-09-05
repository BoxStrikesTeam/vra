"""JSON report generation for VRA."""

from __future__ import annotations

import json
from pathlib import Path

from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding

log = get_logger("reporting.json")


def compute_validation_summary(findings: list[Finding]) -> dict:
    """Aggregate FP-reduction statistics across the finding set.

    A finding is "structurally" demoted/confirmed when the rule-based validation
    stage left a verdict note (``structural validation: ...``); the demotion
    counters below that are driven purely by those notes are what measure the
    FP-reduction stage, independent of the optional AI pass.
    """
    from vra.core.enums import FindingStatus

    demoted = sum(1 for f in findings if f.status is FindingStatus.LIKELY_FALSE_POSITIVE)
    structural_demoted = 0
    structural_confirmed = 0
    by_cwe: dict[str, dict[str, int]] = {}

    for f in findings:
        verdict = (
            FindingStatus.LIKELY_FALSE_POSITIVE if f.false_positive_indicators else None
        )
        if f.validation_info.startswith("structural validation:"):
            if verdict is FindingStatus.LIKELY_FALSE_POSITIVE:
                structural_demoted += 1
            else:
                structural_confirmed += 1
        cwe = f.cwe or "None"
        entry = by_cwe.setdefault(cwe, {"findings": 0, "demoted": 0, "structurally_demoted": 0})
        entry["findings"] += 1
        if verdict is FindingStatus.LIKELY_FALSE_POSITIVE:
            entry["demoted"] += 1
            if f.validation_info.startswith("structural validation:"):
                entry["structurally_demoted"] += 1

    rows = [
        {
            "cwe": cwe,
            "findings": entry["findings"],
            "demoted": entry["demoted"],
            "structurally_demoted": entry["structurally_demoted"],
            "rate": round(entry["demoted"] / entry["findings"], 4) if entry["findings"] else 0.0,
        }
        for cwe, entry in sorted(
            by_cwe.items(), key=lambda kv: kv[1]["findings"], reverse=True
        )
    ]

    return {
        "total_findings": len(findings),
        "demoted_as_fp": demoted,
        "demotion_rate": round(demoted / len(findings), 4) if findings else 0.0,
        "structurally_demoted": structural_demoted,
        "structurally_confirmed": structural_confirmed,
        "by_cwe": rows,
    }


def generate_json_report(findings: list[Finding], context: AnalysisContext, output_dir: Path) -> Path:
    project_name = context.project.name or "Unknown"
    commit = context.run_metadata.commit_hash[:8] if context.run_metadata.commit_hash else "N/A"

    findings_data = []
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        status = f.status.value if hasattr(f.status, "value") else f.status
        reach = f.reachability.value if hasattr(f.reachability, "value") else f.reachability
        ctrl = f.controllability.value if hasattr(f.controllability, "value") else f.controllability

        evidence_data = []
        for e in f.evidence:
            etype = e.type.value if hasattr(e.type, "value") else e.type
            evidence_data.append({"type": etype, "source": e.source, "detail": e.detail})

        from vra.core.enums import FindingStatus

        verdict = status if status == FindingStatus.LIKELY_FALSE_POSITIVE.value else None
        if verdict is None and f.validation_info.startswith("structural validation:"):
            verdict = "confirmed"
        if verdict is None and f.false_positive_indicators:
            verdict = "likely_false_positive"

        findings_data.append(
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "cwe": f.cwe,
                "severity": sev,
                "confidence": f.confidence,
                "priority_score": f.priority_score,
                "file": f.source.file,
                "line": f.source.line,
                "function": f.source.function,
                "tools": f.tools,
                "evidence": evidence_data,
                "reachability": reach,
                "controllability": ctrl,
                "status": status,
                "validation_verdict": verdict,
                "false_positive_indicators": list(f.false_positive_indicators),
                "notes": f.notes,
                "fingerprint": f.fingerprint,
                "attack_surface": f.attack_surface,
                "vendor_source": f.vendor_source,
                "validation_info": f.validation_info,
                "source_snippet": f.source_snippet,
                "call_chain": [
                    {"function": c.function, "file": c.file} for c in f.call_chain
                ],
                "dataflow": [
                    {
                        "variable": s.variable,
                        "location": {
                            "file": s.location.file,
                            "line": s.location.line,
                            "function": s.location.function,
                        }
                        if s.location
                        else None,
                        "description": s.description,
                    }
                    for s in f.dataflow
                ],
            }
        )

    report = {
        "vra_version": "0.1.0",
        "project": project_name,
        "commit": commit,
        "total_findings": len(findings),
        "validation_summary": compute_validation_summary(findings),
        "findings": findings_data,
    }

    ai = context.ai_analysis
    if ai is not None:
        report["ai_assisted_analysis"] = {
            "executive_summary": ai.executive_summary,
            "severity_distribution": ai.severity_distribution,
            "top_priorities": ai.top_priorities,
            "recommendations": ai.recommendations,
            "disclaimer": ai.disclaimer,
            "narratives": [
                {
                    "finding_id": n.finding_id,
                    "title": n.title,
                    "severity": n.severity,
                    "cwe": n.cwe,
                    "cwe_description": n.cwe_description,
                    "location": n.location,
                    "function": n.function,
                    "summary": n.summary,
                    "evidence_notes": n.evidence_notes,
                    "validation_hint": n.validation_hint,
                    "false_positive_note": n.false_positive_note,
                }
                for n in ai.narratives
            ],
        }

    path = output_dir / "vra-report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
