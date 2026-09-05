"""CLI commands to browse the AI purpose (prompt) catalog.

Users pick how they want the AI to help them from this list; the selection is
stored as ``ai.purpose`` in ``vra.yaml`` or passed as ``--ai-purpose`` on the
analyze command.
"""

from __future__ import annotations

import typer

from vra.ai.prompts import get_preset, list_presets
from vra.cli.ui import console

ai_app = typer.Typer(
    name="ai",
    help="Browse AI purpose presets (what the AI should help with)",
    no_args_is_help=True,
)


@ai_app.command("list")
def ai_list() -> None:
    """Show every AI purpose package with its description."""
    presets = list_presets()
    console.print("[bold]AI purpose presets[/bold]")
    console.print("[dim]Pick one with `vra config set ai.purpose <key>` or `--ai-purpose <key>`.[/dim]\n")
    for p in presets:
        console.print(f"[bold cyan]{p.key}[/bold cyan]  ({p.kind})")
        console.print(f"    [bold]{p.name}[/bold]")
        console.print(f"    [dim]{p.description}[/dim]")
    console.print(
        "\n[dim]Usage: vra analyze --ai --ai-purpose <key> <path>[/dim]"
    )
    console.print("[dim]Tip: `vra ai show <key>` prints the actual prompt template.[/dim]")


@ai_app.command("show")
def ai_show(
    purpose: str = typer.Argument(..., help="Preset key, e.g. remediation"),
) -> None:
    """Print the full prompt template for a purpose."""
    try:
        preset = get_preset(purpose)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)
    console.print(f"[bold]{preset.key}[/bold] - {preset.name} ({preset.kind})")
    console.print(preset.description)
    console.print("\n[bold]Prompt template[/bold] ([dim]{context} is replaced with the serialized findings[/dim]):\n")
    console.print(preset.template, soft_wrap=False)


@ai_app.command("active")
def ai_active() -> None:
    """Show which purpose is selected in the effective configuration."""
    from pathlib import Path

    from vra.core.config import load_config

    config = load_config(Path("vra.yaml") if Path("vra.yaml").exists() else None)
    preset = get_preset(config.ai.purpose or "summary")
    state = "enabled" if config.ai.enabled else "disabled"
    console.print(f"[bold]ai.enabled:[/bold] {state}")
    console.print(f"[bold]ai.purpose:[/bold] {preset.key} - {preset.name} ({preset.kind})")
    if preset.kind in ("verify", "advocate"):
        console.print(f"[dim]This purpose also enables ai.validate={config.ai.validate}[/dim]")
