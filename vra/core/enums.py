"""Core enums for VRA."""

from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    NEW = "new"
    REVIEWING = "reviewing"
    LIKELY_VALID = "likely_valid"
    LIKELY_FALSE_POSITIVE = "likely_false_positive"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"


class ReachabilityLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ControllabilityLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class EvidenceType(str, Enum):
    STATIC_ANALYZER = "static_analyzer"
    AST = "ast"
    CFG = "cfg"
    CALL_GRAPH = "call_graph"
    DATAFLOW = "dataflow"
    CUSTOM_RULE = "custom_rule"
    SANITIZER = "sanitizer"
    SOURCE_CONTEXT = "source_context"
    PROJECT_METADATA = "project_metadata"


class BuildSystemType(str, Enum):
    CMAKE = "cmake"
    MESON = "meson"
    AUTOTOOLS = "autotools"
    MAKE = "make"
    UNKNOWN = "unknown"


class AnalysisProfile(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"


class InputSource(str, Enum):
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    IPC = "ipc"
    ENVIRONMENT = "environment"
    CLI = "cli"
    CONFIGURATION = "configuration"
    PRIVILEGED_SERVICE = "privileged_service"
    LIBRARY_API = "library_api"
    PLUGIN_INTERFACE = "plugin_interface"
    UNKNOWN = "unknown"


class RunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ValidationResult(str, Enum):
    CONFIRMED = "confirmed"
    SUSPICIOUS = "suspicious"
    LIKELY_FP = "likely_fp"
