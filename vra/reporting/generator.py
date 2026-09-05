"""Report generator for VRA."""

from __future__ import annotations

from pathlib import Path

from vra.core.enums import ReportFormat
from vra.core.logging import get_logger
from vra.core.models import AnalysisContext
from vra.reporting.html import generate_html_report
from vra.reporting.json_report import generate_json_report
from vra.reporting.markdown import generate_markdown_report

log = get_logger("reporting.generator")


def generate_reports(
    context: AnalysisContext,
    output_dir: Path,
    formats: list[ReportFormat] | None = None,
) -> list[Path]:
    if formats is None:
        formats = [ReportFormat.HTML, ReportFormat.MARKDOWN, ReportFormat.JSON]

    output_dir.mkdir(parents=True, exist_ok=True)
    reports: list[Path] = []

    findings = context.all_findings

    for fmt in formats:
        try:
            if fmt == ReportFormat.HTML:
                path = generate_html_report(findings, context, output_dir)
            elif fmt == ReportFormat.MARKDOWN:
                path = generate_markdown_report(findings, context, output_dir)
            elif fmt == ReportFormat.JSON:
                path = generate_json_report(findings, context, output_dir)
            else:
                continue
            reports.append(path)
            log.info("Generated %s report: %s", fmt.value, path)
        except Exception as e:
            log.error("Failed to generate %s report: %s", fmt.value, e)

    return reports
