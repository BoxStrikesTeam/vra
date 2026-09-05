"""Finding merger for VRA."""

from __future__ import annotations

from collections import defaultdict

from vra.core.logging import get_logger
from vra.core.models import Finding

log = get_logger("correlation.merger")


def merge_findings(findings: list[Finding]) -> list[Finding]:
    groups: dict[str, list[Finding]] = defaultdict(list)

    for finding in findings:
        key = _compute_merge_key(finding)
        groups[key].append(finding)

    merged: list[Finding] = []
    for key, group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
        else:
            merged.append(_merge_findings_group(group))

    log.info("Merged %d findings into %d", len(findings), len(merged))
    return merged


def _compute_merge_key(finding: Finding) -> str:
    file = finding.source.file
    line = finding.source.line
    cwe = finding.cwe
    return f"{file}:{line}:{cwe}"


def _merge_findings_group(group: list[Finding]) -> Finding:
    base = max(group, key=lambda f: f.confidence)

    all_tools = set()
    for f in group:
        all_tools.update(f.tools)
    base.tools = sorted(all_tools)

    confidence_boost = min(0.1 * (len(group) - 1), 0.25)
    base.confidence = min(base.confidence + confidence_boost, 1.0)

    all_fp_indicators = []
    for f in group:
        all_fp_indicators.extend(f.false_positive_indicators)
    base.false_positive_indicators = list(set(all_fp_indicators))

    all_evidence = []
    seen = set()
    for f in group:
        for e in f.evidence:
            key = (e.type.value if hasattr(e.type, "value") else e.type, e.source)
            if key not in seen:
                seen.add(key)
                all_evidence.append(e)
    base.evidence = all_evidence

    return base
