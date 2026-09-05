"""Markdown report generation for VRA."""

from __future__ import annotations

from pathlib import Path

from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding
from vra.reporting.json_report import compute_validation_summary

log = get_logger("reporting.markdown")


def generate_markdown_report(findings: list[Finding], context: AnalysisContext, output_dir: Path) -> Path:
    project_name = context.project.name or "Unknown"
    commit = context.run_metadata.commit_hash[:8] if context.run_metadata.commit_hash else "N/A"

    lines = [
        f"# VRA Report: {project_name}",
        "",
        f"- **Commit:** {commit}",
        f"- **Files analyzed:** {context.project.total_files}",
        f"- **Total findings:** {len(findings)}",
        "",
        "## Severity Distribution",
        "",
    ]

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    for sev in ["critical", "high", "medium", "low"]:
        count = sev_counts.get(sev, 0)
        lines.append(f"- **{sev.upper()}:** {count}")

    lines.extend(["", "## FP Reduction", ""])
    vs = compute_validation_summary(findings)
    lines.extend(
        [
            f"- **Demoted as likely FP:** {vs['demoted_as_fp']}/{vs['total_findings']} "
            f"({vs['demotion_rate']:.1%})",
            f"- **Structurally demoted:** {vs['structurally_demoted']}",
            f"- **Structurally confirmed:** {vs['structurally_confirmed']}",
            "",
            "| CWE | Findings | Demoted | Rate |",
            "|-----|---------:|--------:|-----:|",
        ]
    )
    for row in vs["by_cwe"]:
        if row["findings"] < 5:
            continue
        lines.append(
            f"| {row['cwe']} | {row['findings']} | {row['demoted']} "
            f"| {row['rate']:.1%} |"
        )
    lines.append("")

    lines.extend(["", "## Findings", ""])

    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        lines.extend(
            [
                f"### {f.id} - {f.title}",
                "",
                f"- **Severity:** {sev.upper()}",
                f"- **Confidence:** {f.confidence:.0%}",
                f"- **Priority:** {f.priority_score:.1f}",
                f"- **CWE:** {f.cwe}",
                f"- **Location:** `{f.source.file}:{f.source.line}`",
                f"- **Function:** {f.source.function or 'N/A'}",
                f"- **Detected by:** {', '.join(f.tools) if f.tools else 'N/A'}",
                f"- **Reachability:** {f.reachability.value}",
                f"- **Controllability:** {f.controllability.value}",
                f"- **Status:** {f.status.value}",
            ]
        )
        if f.attack_surface:
            lines.append(f"- **Attack surface:** {f.attack_surface}")
        if f.vendor_source:
            lines.append(f"- **Vendored/3rd-party:** {f.vendor_source}")
        if f.notes:
            lines.append(f"- **Notes:** {f.notes}")
        if f.false_positive_indicators:
            lines.append(f"- **FP indicators:** {'; '.join(f.false_positive_indicators)}")
        if f.call_chain:
            chain_str = " \u2192 ".join(c.function for c in f.call_chain)
            lines.extend(["- **Call chain:**", "", f"    `{chain_str}`", ""])
        if f.dataflow:
            lines.extend(["- **Data flow (tainted to sink):**", ""])
            for s in f.dataflow:
                loc = s.location
                loc_str = f"`{loc.file}:{loc.line}`" if loc and loc.file else "unknown"
                lines.append(f"    - `{s.variable}` at {loc_str} \u2014 {s.description}")
            lines.append("")
        if f.validation_info:
            lines.append(f"- **Validation:** {f.validation_info}")
        lines.append("")

    if context.ai_analysis is not None:
        ai = context.ai_analysis
        lines.extend(["## AI-Assisted Analysis", ""])
        if ai.executive_summary:
            lines.extend([ai.executive_summary, ""])
        if ai.top_priorities:
            lines.extend(["### Priority Findings", ""])
            for p in ai.top_priorities:
                lines.extend([f"- {p}"])
            lines.append("")
        if ai.recommendations:
            lines.extend(["### Recommendations", ""])
            for r in ai.recommendations:
                lines.extend([f"- {r}"])
            lines.append("")
        if ai.disclaimer:
            lines.extend([f"*{ai.disclaimer}*", ""])

    lines.extend(
        [
            "---",
            "",
            "*VRA is a vulnerability research assistance and evidence aggregation tool. "
            "It does not replace manual security review.*",
        ]
    )

    md_content = "\n".join(lines)
    path = output_dir / "vra-report.md"
    path.write_text(md_content, encoding="utf-8")
    return path
