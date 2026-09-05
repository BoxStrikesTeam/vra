"""Input controllability estimation for VRA."""

from __future__ import annotations

from vra.core.enums import ControllabilityLevel
from vra.core.logging import get_logger

log = get_logger("security.controllability")


def estimate_controllability_from_source(source_type: str) -> ControllabilityLevel:
    mapping = {
        "network": ControllabilityLevel.HIGH,
        "ipc": ControllabilityLevel.HIGH,
        "cli": ControllabilityLevel.HIGH,
        "filesystem": ControllabilityLevel.MEDIUM,
        "environment": ControllabilityLevel.MEDIUM,
        "configuration": ControllabilityLevel.MEDIUM,
        "library_api": ControllabilityLevel.LOW,
        "internal": ControllabilityLevel.LOW,
        "unknown": ControllabilityLevel.UNKNOWN,
    }
    return mapping.get(source_type.lower(), ControllabilityLevel.UNKNOWN)
