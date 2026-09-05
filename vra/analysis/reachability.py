"""Reachability analysis for VRA."""

from __future__ import annotations

from vra.core.enums import ReachabilityLevel
from vra.core.logging import get_logger
from vra.core.models import Finding

log = get_logger("analysis.reachability")


def estimate_reachability(finding: Finding) -> ReachabilityLevel:
    if finding.reachability != ReachabilityLevel.UNKNOWN:
        return finding.reachability

    if finding.call_chain:
        chain_len = len(finding.call_chain)
        if chain_len <= 2:
            return ReachabilityLevel.HIGH
        elif chain_len <= 4:
            return ReachabilityLevel.MEDIUM
        else:
            return ReachabilityLevel.LOW

    if finding.source.function:
        if any(kw in finding.source.function.lower() for kw in ["handler", "process", "parse", "main", "entry"]):
            return ReachabilityLevel.HIGH

    return ReachabilityLevel.UNKNOWN
