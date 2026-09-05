"""CWE classification for VRA."""

from __future__ import annotations

CWE_DESCRIPTIONS: dict[str, str] = {
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input",
    "CWE-131": "Incorrect Calculation of Buffer Size",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-401": "Missing Release of Memory after Effective Lifetime",
    "CWE-404": "Improper Resource Shutdown or Release",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-457": "Use of Uninitialized Variable",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-563": "Assignment to Variable without Use",
    "CWE-697": "Incorrect Comparison",
    "CWE-823": "Use of Out-of-range Pointer Offset",
    "CWE-1164": "Unnecessary Code",
    "CWE-0": "Uncategorized",
}

CWE_SEVERITY_BASE: dict[str, str] = {
    "CWE-416": "high",
    "CWE-415": "high",
    "CWE-120": "high",
    "CWE-190": "medium",
    "CWE-476": "medium",
    "CWE-119": "medium",
    "CWE-401": "low",
    "CWE-404": "low",
    "CWE-457": "medium",
    "CWE-502": "high",
}


def get_cwe_description(cwe: str) -> str:
    return CWE_DESCRIPTIONS.get(cwe, "Unknown CWE")


def get_base_severity(cwe: str) -> str:
    return CWE_SEVERITY_BASE.get(cwe, "medium")
