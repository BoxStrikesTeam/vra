"""Call and data flow chain extraction for VRA."""

from __future__ import annotations

from vra.core.logging import get_logger
from vra.core.models import CallChainEntry, DataFlowStep

log = get_logger("evidence.chains")


def build_call_chain_description(chain: list[CallChainEntry]) -> str:
    if not chain:
        return "No call chain available"
    parts = []
    for entry in chain:
        loc = f"{entry.file}:{entry.line}" if entry.file else ""
        parts.append(f"  {entry.function}({loc})")
    return " ->\n".join(parts) if len(parts) > 1 else parts[0]


def build_dataflow_description(steps: list[DataFlowStep]) -> str:
    if not steps:
        return "No dataflow available"
    parts = []
    for step in steps:
        loc = f"{step.location.file}:{step.location.line}" if step.location.file else ""
        parts.append(f"  {step.variable} ({loc}): {step.description}")
    return "\n".join(parts)
