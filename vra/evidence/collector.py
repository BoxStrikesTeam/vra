"""Evidence collection for VRA."""

from __future__ import annotations

from vra.core.enums import EvidenceType
from vra.core.logging import get_logger
from vra.core.models import Evidence, Finding

log = get_logger("evidence.collector")


def collect_evidence(finding: Finding) -> list[Evidence]:
    evidence = finding.evidence.copy()

    if finding.tools:
        for tool in finding.tools:
            if tool.startswith("rule:"):
                evidence.append(
                    Evidence(
                        type=EvidenceType.CUSTOM_RULE,
                        source=tool,
                        detail=f"Matched by custom rule: {tool}",
                    )
                )
            else:
                evidence.append(
                    Evidence(
                        type=EvidenceType.STATIC_ANALYZER,
                        source=tool,
                        detail=f"Detected by {tool}",
                    )
                )

    if finding.dataflow:
        evidence.append(Evidence(type=EvidenceType.DATAFLOW, detail="Dataflow path identified"))

    if finding.call_chain:
        evidence.append(Evidence(type=EvidenceType.CALL_GRAPH, detail="Call chain identified"))

    finding.evidence = evidence
    return evidence
