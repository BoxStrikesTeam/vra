"""Rule engine core for VRA."""

from __future__ import annotations

from pathlib import Path

from vra.core.logging import get_logger
from vra.core.models import Finding, ProjectInfo, RuleContext
from vra.rules.base import SecurityRule
from vra.rules.registry import RuleRegistry

log = get_logger("rules.engine")


class RuleEngine:
    def __init__(self):
        self._rules: list[SecurityRule] = []

    def load_rules(self) -> None:
        from vra.rules.registry import discover_rules

        discover_rules()
        self._rules = RuleRegistry.get_all()
        log.info("Loaded %d rules", len(self._rules))

    def run(self, project: ProjectInfo, workspace_dir: Path) -> list[Finding]:
        if not self._rules:
            self.load_rules()

        all_findings: list[Finding] = []
        source_files = self._get_source_files(project.path)

        for rule in self._rules:
            for source_file in source_files:
                try:
                    context = self._build_context(project, source_file, workspace_dir)
                    findings = rule.analyze(context)
                    all_findings.extend(findings)
                except Exception as e:
                    log.debug("Rule '%s' failed on %s: %s", rule.name, source_file, e)

        log.info("Rule engine produced %d findings", len(all_findings))
        return all_findings

    def _get_source_files(self, project_path: Path) -> list[Path]:
        extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
        files = []
        for f in project_path.rglob("*"):
            if f.is_file() and f.suffix.lower() in extensions:
                if not any(part.startswith(".") for part in f.relative_to(project_path).parts):
                    files.append(f)
        return files[:500]

    def _build_context(self, project: ProjectInfo, file_path: Path, workspace_dir: Path) -> RuleContext:
        content = ""
        try:
            content = file_path.read_text(errors="ignore")
        except OSError:
            pass
        return RuleContext(
            project=project,
            source_dir=project.path,
            file_path=str(file_path),
            file_content=content,
        )
