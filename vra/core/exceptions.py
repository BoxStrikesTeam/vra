"""Core exceptions for VRA."""


class VRAError(Exception):
    """Base exception for all VRA errors."""


class BuildError(VRAError):
    """Build process failed."""


class AnalyzerError(VRAError):
    """Analyzer execution failed."""


class AnalyzerUnavailableError(AnalyzerError):
    """Analyzer tool is not installed or not found."""


class ConfigurationError(VRAError):
    """Invalid configuration."""


class ProjectError(VRAError):
    """Project inspection or detection failed."""


class DatabaseError(VRAError):
    """Database operation failed."""


class RuleError(VRAError):
    """Rule execution failed."""


class ReportError(VRAError):
    """Report generation failed."""


class TimeoutError(VRAError):
    """Process timed out."""


class SecurityError(VRAError):
    """Security constraint violated."""
