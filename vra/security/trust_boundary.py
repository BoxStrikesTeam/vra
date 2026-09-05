"""Trust boundary analysis for VRA."""

from __future__ import annotations

import re

from vra.core.enums import ControllabilityLevel, InputSource
from vra.core.logging import get_logger

log = get_logger("security.trust_boundary")

NETWORK_SOURCES = re.compile(r"\b(recv|recvfrom|accept|read.*socket|inet_|htons|ntohs)\b")
FILE_SOURCES = re.compile(r"\b(fopen|open|fread|read)\b")
ENV_SOURCES = re.compile(r"\b(getenv|environ)\b")
CLI_SOURCES = re.compile(r"\b(argv|getopt|argp)\b")
IPC_SOURCES = re.compile(r"\b(shmget|mmap|pipe|fork|msgget|semget)\b")


def classify_input_source(line: str) -> InputSource:
    if NETWORK_SOURCES.search(line):
        return InputSource.NETWORK
    if FILE_SOURCES.search(line):
        return InputSource.FILESYSTEM
    if ENV_SOURCES.search(line):
        return InputSource.ENVIRONMENT
    if CLI_SOURCES.search(line):
        return InputSource.CLI
    if IPC_SOURCES.search(line):
        return InputSource.IPC
    return InputSource.UNKNOWN


def estimate_controllability(source: InputSource) -> ControllabilityLevel:
    mapping = {
        InputSource.NETWORK: ControllabilityLevel.HIGH,
        InputSource.IPC: ControllabilityLevel.HIGH,
        InputSource.FILESYSTEM: ControllabilityLevel.MEDIUM,
        InputSource.CLI: ControllabilityLevel.HIGH,
        InputSource.ENVIRONMENT: ControllabilityLevel.MEDIUM,
        InputSource.CONFIGURATION: ControllabilityLevel.MEDIUM,
        InputSource.LIBRARY_API: ControllabilityLevel.LOW,
        InputSource.UNKNOWN: ControllabilityLevel.UNKNOWN,
    }
    return mapping.get(source, ControllabilityLevel.UNKNOWN)
