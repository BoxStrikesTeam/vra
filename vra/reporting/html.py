"""HTML report generation for VRA."""

from __future__ import annotations

from pathlib import Path

from vra.core.logging import get_logger
from vra.core.models import AnalysisContext, Finding

log = get_logger("reporting.html")


def generate_html_report(findings: list[Finding], context: AnalysisContext, output_dir: Path) -> Path:
    project_name = context.project.name or "Unknown"
    commit = context.run_metadata.commit_hash[:8] if context.run_metadata.commit_hash else "N/A"
    total_files = context.project.total_files
    total_findings = len(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    confidence_counts = {"high": 0, "medium": 0, "low": 0}

    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if f.confidence >= 0.7:
            confidence_counts["high"] += 1
        elif f.confidence >= 0.4:
            confidence_counts["medium"] += 1
        else:
            confidence_counts["low"] += 1

    findings_html = ""
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        sev_color = {
            "critical": "#dc2626",
            "high": "#ef4444",
            "medium": "#f59e0b",
            "low": "#06b6d4",
        }.get(sev, "#6b7280")
        conf_pct = f"{f.confidence:.0%}"
        tools_list = ", ".join(f.tools) if f.tools else "N/A"
        evidence_count = len(f.evidence)

        evidence_items = ""
        for e in f.evidence:
            etype = e.type.value if hasattr(e.type, "value") else e.type
            evidence_items += f'<li><span class="evidence-type">{etype}</span> {e.source}: {e.detail}</li>\n'

        chain_html = ""
        if f.call_chain:
            chain_parts = " &rarr; ".join(e.function for e in f.call_chain)
            chain_html = f'<p><strong>Call chain:</strong> <span class="chain">{chain_parts}</span></p>'

        snippet_html = ""
        if f.source_snippet:
            snippet_html = f'<pre class="snippet">{f.source_snippet}</pre>'

        dataflow_html = ""
        if f.dataflow:
            parts = []
            for s in f.dataflow:
                loc = s.location
                loc_txt = f"{loc.file}:{loc.line}" if loc and loc.file else "unknown"
                parts.append(
                    f'<li><code>{s.variable}</code> @ {loc_txt} &mdash; {s.description}</li>'
                )
            dataflow_html = (
                '<h4>Taint data flow</h4><ul class="dataflow">' + "".join(parts) + "</ul>"
            )

        findings_html += f'''
        <div class="finding" id="{f.id}">
            <div class="finding-header">
                <span class="finding-id">{f.id}</span>
                <span class="severity-badge" style="background:{sev_color}">{sev.upper()}</span>
                <span class="confidence">{conf_pct} confidence</span>
                <span class="priority">Priority: {f.priority_score:.1f}</span>
            </div>
            <h3>{f.title}</h3>
            <div class="finding-meta">
                <span class="cwe">{f.cwe}</span>
                <span class="location">{f.source.file}:{f.source.line}</span>
                <span class="function">{f.source.function or "N/A"}</span>
            </div>
            <div class="finding-details">
                <p><strong>Detected by:</strong> {tools_list}</p>
                <p><strong>Evidence count:</strong> {evidence_count}</p>
                <p><strong>Reachability:</strong> {f.reachability.value}</p>
                <p><strong>Controllability:</strong> {f.controllability.value}</p>
                <p><strong>Status:</strong> {f.status.value}</p>
                {f"<p><strong>FP indicators:</strong> {'; '.join(f.false_positive_indicators)}</p>" if f.false_positive_indicators else ""}
                {f"<p><strong>Validation:</strong> {f.validation_info}</p>" if f.validation_info else ""}
                {f"<p><strong>Attack surface:</strong> {f.attack_surface}</p>" if f.attack_surface else ""}
                {f"<p><strong>Vendored/3rd-party:</strong> {f.vendor_source}</p>" if f.vendor_source else ""}
                {f"<p><strong>Notes:</strong> {f.notes}</p>" if f.notes else ""}
                {chain_html}
            </div>
            {f"<h4>Evidence</h4><ul>{evidence_items}</ul>" if evidence_items else ""}
            {dataflow_html}
            {snippet_html}
        </div>
        '''

    ai_html = ""
    if context.ai_analysis is not None:
        ai = context.ai_analysis
        ai_html = '<h2 class="section-title">AI-Assisted Analysis</h2>'
        if ai.executive_summary:
            ai_html += f'<div class="ai-summary">{ai.executive_summary}</div>'
        if ai.top_priorities:
            ai_html += "<h4>Priority Findings</h4><ul>"
            for p in ai.top_priorities:
                ai_html += f"<li>{p}</li>"
            ai_html += "</ul>"
        if ai.recommendations:
            ai_html += "<h4>Recommendations</h4><ul>"
            for r in ai.recommendations:
                ai_html += f"<li>{r}</li>"
            ai_html += "</ul>"
        if ai.disclaimer:
            ai_html += f'<p class="ai-disclaimer">{ai.disclaimer}</p>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VRA Report - {project_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        h1 {{ color: #38bdf8; margin-bottom: 0.5rem; font-size: 1.8rem; }}
        .subtitle {{ color: #94a3b8; margin-bottom: 2rem; }}
        .dashboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.2rem; text-align: center; }}
        .stat-value {{ font-size: 2rem; font-weight: 700; color: #38bdf8; }}
        .stat-label {{ color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; }}
        .finding {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }}
        .finding-header {{ display: flex; gap: 0.8rem; align-items: center; margin-bottom: 0.8rem; flex-wrap: wrap; }}
        .finding-id {{ font-family: monospace; color: #38bdf8; font-weight: 700; }}
        .severity-badge {{ padding: 2px 8px; border-radius: 4px; color: white; font-size: 0.75rem; font-weight: 600; }}
        .confidence {{ color: #94a3b8; font-size: 0.85rem; }}
        .priority {{ color: #facc15; font-size: 0.85rem; font-weight: 600; }}
        .finding h3 {{ margin-bottom: 0.5rem; color: #f1f5f9; }}
        .finding-meta {{ display: flex; gap: 1rem; color: #94a3b8; font-size: 0.85rem; margin-bottom: 0.8rem; }}
        .finding-details p {{ margin-bottom: 0.3rem; font-size: 0.9rem; }}
        .evidence-type {{ background: #334155; padding: 1px 6px; border-radius: 3px; font-size: 0.75rem; }}
        .snippet {{ background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 1rem; overflow-x: auto; font-size: 0.85rem; margin-top: 0.5rem; }}
        ul {{ padding-left: 1.5rem; margin: 0.5rem 0; }}
        li {{ font-size: 0.85rem; margin-bottom: 0.3rem; }}
        .section-title {{ color: #38bdf8; font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
        .ai-summary {{ background: #1e293b; border-left: 4px solid #38bdf8; padding: 1rem; border-radius: 4px; margin-bottom: 1rem; }}
        .ai-disclaimer {{ color: #94a3b8; font-size: 0.8rem; font-style: italic; margin-top: 1rem; }}
        .chain {{ color: #facc15; font-family: monospace; }}
    </style>
</head>
<body>
<div class="container">
    <h1>VRA - Vulnerability Research Report</h1>
    <p class="subtitle">Project: {project_name} | Commit: {commit}</p>

    <div class="dashboard">
        <div class="stat"><div class="stat-value">{total_files}</div><div class="stat-label">Files Analyzed</div></div>
        <div class="stat"><div class="stat-value">{total_findings}</div><div class="stat-label">Total Findings</div></div>
        <div class="stat"><div class="stat-value" style="color:#ef4444">{severity_counts.get("critical", 0) + severity_counts.get("high", 0)}</div><div class="stat-label">Critical + High</div></div>
        <div class="stat"><div class="stat-value" style="color:#f59e0b">{severity_counts.get("medium", 0)}</div><div class="stat-label">Medium</div></div>
        <div class="stat"><div class="stat-value" style="color:#06b6d4">{severity_counts.get("low", 0)}</div><div class="stat-label">Low</div></div>
        <div class="stat"><div class="stat-value">{confidence_counts["high"]}</div><div class="stat-label">High Confidence</div></div>
    </div>

    <h2 class="section-title">Findings ({total_findings})</h2>
    {findings_html if findings_html else '<p style="color:#94a3b8">No findings.</p>'}

    {ai_html}
</div>
</body>
</html>"""

    path = output_dir / "vra-report.html"
    path.write_text(html, encoding="utf-8")
    return path
