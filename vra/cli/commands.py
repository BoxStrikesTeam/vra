"""CLI commands for VRA."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import typer

from vra.analyzers.registry import AnalyzerRegistry, discover_analyzers
from vra.cli.ui import (
    console,
    print_doctor_table,
    print_findings_table,
    print_summary,
)
from vra.core.config import load_config
from vra.core.enums import ReportFormat
from vra.core.logging import get_logger, setup_logging
from vra.core.orchestrator import Orchestrator
from vra.project.inspector import inspect_project
from vra.reporting.generator import generate_reports
from vra.rules.registry import RuleRegistry

log = get_logger("cli.commands")

WORKSPACE_DIR = Path.cwd() / ".vra-workspace"
REPORTS_DIR = WORKSPACE_DIR / "reports"

_URL_RE = re.compile(r"^(?:https?://|git@|git://|ssh://).+")


def _resolve_source(path: str, workspace: Path, log) -> Path:
    """Resolve a local path or clone a remote git URL into the workspace."""
    if not _URL_RE.search(path):
        return Path(path)

    log.info("Detected remote URL, cloning %s ...", path)
    clone_dir = workspace / "src"
    clone_dir.mkdir(parents=True, exist_ok=True)

    if (clone_dir / ".git").exists():
        log.info("Updating existing clone in %s", clone_dir)
        subprocess.run(["git", "-C", str(clone_dir), "pull", "--ff-only"], check=False)
        return clone_dir

    result = subprocess.run(
        ["git", "clone", "--depth", "1", path, str(clone_dir)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        console.print(f"[red]Failed to clone {path}: {result.stderr.strip()}[/red]")
        raise typer.Exit(1)
    log.info("Cloned into %s", clone_dir)
    return clone_dir


_SOURCE_EXTS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}


def _warn_on_empty_source(source_path: Path, original: str, log) -> None:
    """Warn loudly when the resolved path yields no source code.

    Prevents a silent no-op run (Files analyzed: 0, 0 findings) caused by a
    wrong/missing path that shares its basename with the intended target
    (e.g. resolving ``zeek`` to a nonexistent ``/root/root/zeek``).
    """
    if not source_path.exists():
        console.print(f"[yellow]Warning: path does not exist: {source_path}[/yellow]")
        console.print(f"[yellow]Requested '{original}' — did you mean an absolute path to the project?[/yellow]")
        return

    if source_path.is_dir():
        has_source = any(
            f.is_file() and f.suffix.lower() in _SOURCE_EXTS for f in source_path.rglob("*")
        )
        if not has_source:
            console.print(
                f"[yellow]Warning: no source files found under {source_path} "
                f"(Files analyzed will be 0). Check the project path.[/yellow]"
            )
            return


def init_command():
    """Initialize VRA workspace."""
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    console.print("[green]VRA workspace initialized[/green]")


def inspect_command(
    path: str = typer.Argument(".", help="Path to the project to inspect"),
):
    """Inspect a project and show its metadata."""
    project_path = Path(path)
    project_info = inspect_project(project_path)

    console.print(f"[bold]Project:[/bold] {project_info.name}")
    console.print(f"[bold]Languages:[/bold] {', '.join(project_info.languages) or 'N/A'}")
    console.print(f"[bold]C ratio:[/bold] {project_info.c_ratio:.0%}")
    console.print(f"[bold]C++ ratio:[/bold] {project_info.cpp_ratio:.0%}")
    console.print(f"[bold]Build system:[/bold] {project_info.build_system.value}")
    console.print(f"[bold]Compiler:[/bold] {project_info.compiler}")
    console.print(f"[bold]Architecture:[/bold] {project_info.architecture}")
    console.print(f"[bold]Tests:[/bold] {'Yes' if project_info.has_tests else 'No'}")
    console.print(f"[bold]Network code:[/bold] {'Yes' if project_info.has_network_code else 'No'}")
    console.print(f"[bold]Parser code:[/bold] {'Yes' if project_info.has_parser_code else 'No'}")
    console.print(f"[bold]IPC code:[/bold] {'Yes' if project_info.has_ipc_code else 'No'}")
    console.print(
        f"[bold]Files:[/bold] {project_info.total_files} (C: {project_info.c_files}, C++: {project_info.cpp_files}, headers: {project_info.header_files})"  # noqa: E501
    )


def analyze_command(
    path: str = typer.Argument(".", help="Path or URL to the project to analyze"),
    profile: str = typer.Option("standard", "--profile", "-p", help="Analysis profile: quick, standard, deep"),
    format: str = typer.Option("all", "--format", "-f", help="Report formats: all, html, markdown, json"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ai_enabled: bool = typer.Option(False, "--ai", help="Enable AI-assisted narrative analysis"),
    ai_model: str = typer.Option("", "--ai-model", help="Model identifier for AI analysis"),
    validate: bool = typer.Option(False, "--validate", help="Enable FP validation (rule-based + optional AI passes)"),
    drop_fp: bool = typer.Option(False, "--drop-fp", help="Exclude likely-false-positive findings from reports"),
):
    """Run the full analysis pipeline on a project."""
    setup_logging(verbose=verbose)
    config = load_config()
    config.profile = profile
    if ai_enabled:
        config.ai.enabled = True
    if ai_model:
        config.ai.enabled = True
        config.ai.model = ai_model
    if validate:
        config.ai.validate = True

    source_path = _resolve_source(path, WORKSPACE_DIR, log)

    # Guard against silent no-op runs when the path is wrong or holds no source.
    _warn_on_empty_source(source_path, path, log)

    from vra.cli.ui import print_completion, show_progress

    orchestrator = Orchestrator(
        config,
        WORKSPACE_DIR,
        progress_callback=show_progress,
    )
    start_time = time.monotonic()
    context = orchestrator.analyze(source_path)
    elapsed = time.monotonic() - start_time

    if drop_fp:
        from vra.core.enums import FindingStatus

        fp_findings = [f for f in context.all_findings if f.status == FindingStatus.LIKELY_FALSE_POSITIVE]
        if fp_findings:
            console.print(
                f"[dim]--drop-fp: excluding {len(fp_findings)} likely-false-positive "
                f"finding(s) from reports.[/dim]"
            )
            context.all_findings = [f for f in context.all_findings if f not in fp_findings]

    formats = []
    if format == "all":
        formats = [ReportFormat.HTML, ReportFormat.MARKDOWN, ReportFormat.JSON]
    else:
        format_map = {
            "html": ReportFormat.HTML,
            "markdown": ReportFormat.MARKDOWN,
            "md": ReportFormat.MARKDOWN,
            "json": ReportFormat.JSON,
        }
        fmt = format_map.get(format.lower())
        if fmt:
            formats = [fmt]
        else:
            formats = [ReportFormat.HTML, ReportFormat.MARKDOWN, ReportFormat.JSON]

    reports = generate_reports(context, REPORTS_DIR, formats)

    findings = context.all_findings
    confidence_high = sum(1 for f in findings if f.confidence >= 0.7)
    confidence_medium = sum(1 for f in findings if 0.4 <= f.confidence < 0.7)
    confidence_low = sum(1 for f in findings if f.confidence < 0.4)

    from vra.core.enums import RunStatus

    failed_tools = [tr.analyzer_name for tr in context.tool_results if tr.status == RunStatus.FAILED]

    print_summary(
        files_analyzed=context.project.total_files,
        analyzer_findings=sum(len(tr.findings) for tr in context.tool_results),
        correlated_findings=len(findings),
        high_confidence=confidence_high,
        medium_confidence=confidence_medium,
        low_confidence=confidence_low,
        reports=[str(r) for r in reports],
        findings=findings,
        failed_tools=failed_tools or None,
    )

    print_completion(
        summary="Analysis complete",
        findings_count=len(findings),
        duration=elapsed,
        reports=[str(r) for r in reports],
        reports_dir=str(REPORTS_DIR),
    )


def findings_command(
    limit: int = typer.Option(50, "--limit", "-l", help="Number of findings to show"),
    severity: str = typer.Option(None, "--severity", "-s", help="Filter by severity"),
):
    """List findings from the current analysis."""
    from vra.storage.database import Database

    db = Database(WORKSPACE_DIR / "vra.db")
    findings = db.get_findings(limit=limit)

    from vra.core.models import Finding

    models = []
    for fm in findings:
        models.append(
            Finding(
                id=fm.finding_id,
                title=fm.title,
                category=fm.category,
                cwe=fm.cwe,
                severity=fm.severity,
                confidence=fm.confidence or 0.0,
                source=__import__("vra.core.models", fromlist=["SourceLocation"]).SourceLocation(
                    file=fm.file_path or "", line=fm.line or 0, function=fm.function_name or ""
                ),
                tools=fm.tools.split(",") if fm.tools else [],
                priority_score=fm.priority_score or 0.0,
            )
        )

    if severity:
        models = [f for f in models if f.severity.value == severity]
    print_findings_table(models)


def report_command(
    format: str = typer.Option("html", "--format", "-f", help="Report format: html, markdown, json"),
):
    """Generate reports from the current analysis."""
    from vra.core.models import AnalysisContext, RunMetadata

    context = AnalysisContext(
        project=inspect_project(Path.cwd()),
        run_metadata=RunMetadata(),
        workspace_dir=WORKSPACE_DIR,
        source_dir=Path.cwd(),
    )

    from vra.storage.database import Database

    db = Database(WORKSPACE_DIR / "vra.db")
    findings = db.get_findings(limit=1000)

    from vra.core.models import Finding, SourceLocation

    models = []
    for fm in findings:
        models.append(
            Finding(
                id=fm.finding_id,
                title=fm.title,
                category=fm.category,
                cwe=fm.cwe,
                severity=fm.severity,
                confidence=fm.confidence or 0.0,
                source=SourceLocation(file=fm.file_path or "", line=fm.line or 0, function=fm.function_name or ""),
                tools=fm.tools.split(",") if fm.tools else [],
                priority_score=fm.priority_score or 0.0,
            )
        )
    context.all_findings = models

    formats = {
        "html": [ReportFormat.HTML],
        "markdown": [ReportFormat.MARKDOWN],
        "md": [ReportFormat.MARKDOWN],
        "json": [ReportFormat.JSON],
        "all": [ReportFormat.HTML, ReportFormat.MARKDOWN, ReportFormat.JSON],
    }
    fmt_list = formats.get(format.lower(), [ReportFormat.HTML])
    reports = generate_reports(context, REPORTS_DIR, fmt_list)
    for r in reports:
        console.print(f"[green]Report:[/green] {r}")


def rule_list_command():
    """List all available security rules."""
    from vra.rules.registry import discover_rules

    discover_rules()
    rules = RuleRegistry.get_all()
    console.print(f"[bold]Rules ({len(rules)}):[/bold]")
    for rule in rules:
        console.print(f"  [cyan]{rule.name}[/cyan] [{rule.cwe}] - {rule.description}")


rule_app = typer.Typer(help="Manage security rules", no_args_is_help=True)


@rule_app.command("list")
def rule_list():
    """List all available security rules."""
    rule_list_command()


def analyzer_list_command():
    """List all available analyzers."""
    discover_analyzers()
    analyzers = AnalyzerRegistry.get_all()
    console.print(f"[bold]Analyzers ({len(analyzers)}):[/bold]")
    for analyzer in analyzers:
        status = "[green]available[/green]" if analyzer.available() else "[red]unavailable[/red]"
        console.print(f"  [cyan]{analyzer.name}[/cyan] - {status}")


analyzer_app = typer.Typer(help="Manage analyzers", no_args_is_help=True)


@analyzer_app.command("list")
def analyzer_list():
    """List all available analyzers."""
    analyzer_list_command()


def finding_show_command(finding_id: str):
    """Show details of a specific finding."""
    from vra.storage.database import Database

    db = Database(WORKSPACE_DIR / "vra.db")
    fm = db.get_finding_by_id(finding_id)

    if not fm:
        console.print(f"[red]Finding {finding_id} not found[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]ID:[/bold] {fm.finding_id}")
    console.print(f"[bold]Title:[/bold] {fm.title}")
    console.print(f"[bold]Category:[/bold] {fm.category}")
    console.print(f"[bold]CWE:[/bold] {fm.cwe}")
    console.print(f"[bold]Severity:[/bold] {fm.severity}")
    console.print(f"[bold]Confidence:[/bold] {fm.confidence:.0%}")
    console.print(f"[bold]Priority:[/bold] {fm.priority_score:.1f}")
    console.print(f"[bold]Location:[/bold] {fm.file_path}:{fm.line} ({fm.function_name})")
    console.print(f"[bold]Tools:[/bold] {fm.tools}")
    console.print(f"[bold]Status:[/bold] {fm.status}")
    if fm.notes:
        console.print(f"[bold]Notes:[/bold] {fm.notes}")
    if fm.source_snippet:
        console.print("[bold]Snippet:[/bold]")
        console.print(fm.source_snippet)


finding_app = typer.Typer(help="Manage findings", no_args_is_help=True)


@finding_app.command("show")
def finding_show(
    finding_id: str = typer.Argument(..., help="Finding ID (e.g., F-00001)"),
):
    """Show details of a specific finding."""
    finding_show_command(finding_id)


def doctor_command():
    """Check the environment for available tools."""
    tools_to_check = [
        "python3",
        "git",
        "clang",
        "clang-tidy",
        "codeql",
        "semgrep",
        "cppcheck",
        "flawfinder",
        "cmake",
        "meson",
        "ninja",
        "valgrind",
        "gcc",
        "make",
    ]

    results = []
    for tool in tools_to_check:
        path = shutil.which(tool)
        version = ""
        if path:
            try:
                result = subprocess.run(
                    [tool, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")
                    version = lines[0][:80] if lines else ""
            except (subprocess.TimeoutExpired, OSError):
                pass
        results.append({"name": tool, "available": path is not None, "version": version})

    print_doctor_table(results)
    missing = [r["name"] for r in results if not r["available"]]
    if missing:
        console.print(f"\n[yellow]Missing tools:[/yellow] {', '.join(missing)}")
        console.print("[dim]Install missing tools to enable full analysis capabilities.[/dim]")
    else:
        console.print("\n[green]All tools available![/green]")

    from vra.cli.config_command import config_doctor

    config_doctor()


def clean_command():
    """Clean the VRA workspace."""
    if WORKSPACE_DIR.exists():
        shutil.rmtree(WORKSPACE_DIR)
        console.print("[green]Workspace cleaned[/green]")
    else:
        console.print("[dim]Workspace already clean[/dim]")


def test_command():
    """Run the VRA test suite."""
    import pytest

    tests_dir = Path(__file__).parent.parent.parent / "tests"
    if not tests_dir.exists():
        console.print("[red]No tests directory found[/red]")
        raise typer.Exit(1)
    sys.exit(pytest.main([str(tests_dir), "-v"]))
