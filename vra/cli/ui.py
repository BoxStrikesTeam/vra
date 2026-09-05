"""Rich-based terminal UI for VRA."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.theme import Theme

VRA_THEME = Theme(
    {
        "info": "cyan",
        "success": "green",
        "warning": "yellow",
        "error": "red bold",
        "highlight": "bold magenta",
    }
)

console = Console(theme=VRA_THEME)


def print_banner() -> None:
    banner = "[bold cyan]VRA[/bold cyan] - [dim]Vulnerability Research Automation[/dim]"
    console.print(Panel(banner, border_style="cyan"))


def print_step(current: int, total: int, message: str, status: str = "") -> None:
    status_color = {
        "OK": "[green]OK[/green]",
        "SKIP": "[yellow]SKIP[/yellow]",
        "FAIL": "[red]FAIL[/red]",
    }.get(status, "")
    step = f"[dim][{current}/{total}][/dim] {message}"
    if status_color:
        step += f" {status_color}"
    console.print(step)


def show_progress(current: int, total: int, message: str) -> None:
    """Print a live progress line with percentage, e.g. [3/7] 43% Running..."""
    percent = round((current / total) * 100) if total > 0 else 0
    console.print(f"[bold cyan][{current}/{total}][/bold cyan] [magenta]{percent:3d}%[/magenta] {message}")


def print_completion(
    summary: str,
    findings_count: int,
    duration: float,
    reports: list[str] | None = None,
    reports_dir: str = "",
) -> None:
    """Print an unmissable 'analysis complete' panel."""
    lines = [
        "[bold green]✔ ANALİZ TAMAMLANDI[/bold green]",
        f"[bold]{findings_count}[/bold] related finding(s)",
        f"Elapsed: [green]{duration:.1f}s[/green]",
    ]
    body = "\n".join(lines)
    panel = Panel(body, border_style="green", title="[bold green]Done[/bold green]")
    console.print()
    console.print(panel)
    console.print(f"[dim]Reports written to:[/dim] {reports_dir or (reports[0] if reports else '')}")


def print_summary(
    files_analyzed: int = 0,
    functions_analyzed: int = 0,
    analyzer_findings: int = 0,
    correlated_findings: int = 0,
    high_confidence: int = 0,
    medium_confidence: int = 0,
    low_confidence: int = 0,
    reports: list[str] | None = None,
    findings: list | None = None,
    failed_tools: list[str] | None = None,
) -> None:
    console.print()
    table = Table(title="Analysis Summary", border_style="cyan")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")
    table.add_row("Files analyzed", str(files_analyzed))
    table.add_row("Analyzer findings", str(analyzer_findings))
    table.add_row("Correlated findings", str(correlated_findings))
    table.add_row("High confidence", f"[green]{high_confidence}[/green]")
    table.add_row("Medium confidence", f"[yellow]{medium_confidence}[/yellow]")
    table.add_row("Low confidence", f"[red]{low_confidence}[/red]")
    console.print(table)

    if findings:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        file_counts: dict[str, int] = {}
        cwe_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            fname = f.source.file
            file_counts[fname] = file_counts.get(fname, 0) + 1
            if f.cwe:
                cwe_counts[f.cwe] = cwe_counts.get(f.cwe, 0) + 1

        sev_table = Table(title="Severity Distribution", border_style="cyan")
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")
        for sev in ("critical", "high", "medium", "low"):
            color = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "cyan"}.get(sev, "white")
            sev_table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(severity_counts.get(sev, 0)))
        console.print(sev_table)

        if cwe_counts:
            cwe_table = Table(title="Top CWEs", border_style="cyan")
            cwe_table.add_column("CWE")
            cwe_table.add_column("Count", justify="right")
            for cwe, count in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                cwe_table.add_row(cwe, str(count))
            console.print(cwe_table)

        if file_counts:
            file_table = Table(title="Most Affected Files", border_style="cyan")
            file_table.add_column("File")
            file_table.add_column("Findings", justify="right")
            for fname, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                short = fname.rsplit("/", 1)[-1] if "/" in fname else fname
                file_table.add_row(short, str(count))
            console.print(file_table)

    if failed_tools:
        console.print(f"\n[yellow]Analyzers that failed:[/yellow] {', '.join(failed_tools)}")
        console.print("[dim]These may be due to missing tools or configuration; see logs for details.[/dim]")

    if reports:
        console.print("\n[bold]Reports:[/bold]")
        for r in reports:
            console.print(f"  {r}")


def print_findings_table(findings: list) -> None:
    if not findings:
        console.print("[dim]No findings.[/dim]")
        return

    table = Table(title="Findings", border_style="cyan")
    table.add_column("ID", style="highlight")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Confidence", justify="right")
    table.add_column("CWE")
    table.add_column("Location")

    severity_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
    }

    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        color = severity_colors.get(sev, "white")
        conf = f"{f.confidence:.0%}" if f.confidence else "N/A"
        loc = f"{f.source.file}:{f.source.line}" if f.source.file else "N/A"
        table.add_row(
            f.id,
            f.title,
            f"[{color}]{sev.upper()}[/{color}]",
            conf,
            f.cwe,
            loc,
        )
    console.print(table)


def print_doctor_table(tools: list[dict]) -> None:
    table = Table(title="Environment Check", border_style="cyan")
    table.add_column("Tool", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Version", style="dim")

    for tool in tools:
        status = "[green]OK[/green]" if tool["available"] else "[red]MISSING[/red]"
        version = tool.get("version", "")
        table.add_row(tool["name"], status, version)
    console.print(table)


def create_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    )
