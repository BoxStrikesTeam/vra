"""Core data models for VRA."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vra.core.enums import (
    BuildSystemType,
    ControllabilityLevel,
    EvidenceType,
    FindingStatus,
    ReachabilityLevel,
    RunStatus,
    Severity,
)


@dataclass
class SourceLocation:
    file: str
    line: int
    column: int = 0
    function: str = ""


@dataclass
class Evidence:
    type: EvidenceType
    source: str = ""
    detail: str = ""


@dataclass
class DataFlowStep:
    variable: str
    location: SourceLocation
    description: str = ""


@dataclass
class CallChainEntry:
    function: str
    file: str = ""
    line: int = 0


@dataclass
class Finding:
    id: str
    title: str
    category: str
    cwe: str
    severity: Severity
    confidence: float
    source: SourceLocation
    tools: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    dataflow: list[DataFlowStep] = field(default_factory=list)
    call_chain: list[CallChainEntry] = field(default_factory=list)
    reachability: ReachabilityLevel = ReachabilityLevel.UNKNOWN
    controllability: ControllabilityLevel = ControllabilityLevel.UNKNOWN
    status: FindingStatus = FindingStatus.NEW
    notes: str = ""
    fingerprint: str = ""
    priority_score: float = 0.0
    attack_surface: str = ""
    validation_info: str = ""
    false_positive_indicators: list[str] = field(default_factory=list)
    source_snippet: str = ""
    vendor_source: str = ""

    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if isinstance(self.reachability, str):
            self.reachability = ReachabilityLevel(self.reachability)
        if isinstance(self.controllability, str):
            self.controllability = ControllabilityLevel(self.controllability)
        if isinstance(self.status, str):
            self.status = FindingStatus(self.status)


@dataclass
class ProjectInfo:
    name: str = ""
    path: Path = field(default_factory=Path)
    languages: list[str] = field(default_factory=list)
    c_ratio: float = 0.0
    cpp_ratio: float = 0.0
    build_system: BuildSystemType = BuildSystemType.UNKNOWN
    compiler: str = ""
    architecture: str = ""
    has_tests: bool = False
    has_network_code: bool = False
    has_parser_code: bool = False
    has_ipc_code: bool = False
    has_privileged_code: bool = False
    executable_count: int = 0
    shared_lib_count: int = 0
    static_lib_count: int = 0
    total_files: int = 0
    c_files: int = 0
    cpp_files: int = 0
    header_files: int = 0
    dependencies: list[str] = field(default_factory=list)


@dataclass
class BuildResult:
    status: RunStatus
    compile_commands_path: Path | None = None
    build_dir: Path | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration: float = 0.0
    return_code: int = 0
    message: str = ""


@dataclass
class ToolRunResult:
    analyzer_name: str
    raw_output: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    status: RunStatus = RunStatus.PENDING
    error_message: str = ""


@dataclass
class RunMetadata:
    repo_url: str = ""
    commit_hash: str = ""
    branch: str = ""
    timestamp: str = ""
    compiler_version: str = ""
    tool_versions: dict[str, str] = field(default_factory=dict)
    config_hash: str = ""
    os_name: str = ""
    architecture: str = ""
    profile: str = "standard"
    enabled_analyzers: list[str] = field(default_factory=list)
    enabled_rules: list[str] = field(default_factory=list)


@dataclass
class AnalysisContext:
    project: ProjectInfo
    build_result: BuildResult | None = None
    run_metadata: RunMetadata = field(default_factory=RunMetadata)
    workspace_dir: Path = field(default_factory=Path)
    source_dir: Path = field(default_factory=Path)
    all_findings: list[Finding] = field(default_factory=list)
    tool_results: list[ToolRunResult] = field(default_factory=list)
    ai_analysis: object | None = None


@dataclass
class RuleContext:
    project: ProjectInfo
    source_dir: Path
    file_path: str = ""
    file_content: str = ""
    compilation_db_path: Path | None = None
