"""Finding deduplication for VRA."""

from __future__ import annotations

from collections import defaultdict

from vra.core.logging import get_logger
from vra.core.models import Finding
from vra.correlation.fingerprint import compute_fingerprint

log = get_logger("correlation.deduplicator")


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    groups: dict[str, list[Finding]] = defaultdict(list)

    for finding in findings:
        fp = compute_fingerprint(finding)
        finding.fingerprint = fp
        groups[fp].append(finding)

    merged: list[Finding] = []
    for fp, group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
        else:
            merged.append(_merge_group(group))

    log.info("Deduplicated %d findings -> %d", len(findings), len(merged))
    return merged


def _merge_group(group: list[Finding]) -> Finding:
    base = group[0]

    all_tools = set()
    for f in group:
        all_tools.update(f.tools)
    base.tools = list(all_tools)

    confidence_boost = min(0.15 * (len(group) - 1), 0.3)
    base.confidence = min(base.confidence + confidence_boost, 1.0)

    all_evidence = []
    seen_types = set()
    for f in group:
        for e in f.evidence:
            key = (e.type, e.source)
            if key not in seen_types:
                seen_types.add(key)
                all_evidence.append(e)
    base.evidence = all_evidence

    return base
