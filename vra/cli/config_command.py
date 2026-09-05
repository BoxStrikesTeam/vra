"""CLI commands to view and edit VRA configuration (vra.yaml)."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from pathlib import Path

import typer
import yaml

from vra.cli.ui import console
from vra.core.config import load_config

config_app = typer.Typer(
    name="config",
    help="View or edit VRA configuration (vra.yaml in the current directory)",
    no_args_is_help=True,
)

_DEFAULT_CONFIG_PATH = Path("vra.yaml")

VRA_CONFIG_TEMPLATE = """\
# VRA configuration
# Place this file as `vra.yaml` in the directory where you run `vra analyze`.

analysis:
  profile: standard          # quick | standard | deep

analyzers:
  clang_tidy: true
  clang_analyzer: true
  codeql: true
  semgrep: true
  cppcheck: true
  flawfinder: false
  sanitizer: false           # enable to attempt ASan/UBSan build+run

rules: {}                    # all rule categories are enabled by default

ai:
  enabled: false             # master switch for AI narratives (or pass --ai)
  provider: local
  model: ""                  # free-text model label (used in logs & reports)

  # model_command runs your LLM as a subprocess. The prompt is sent on stdin
  # and the model's answer is read from stdout (so the command must support
  # pipe mode). Example with Ollama:
  #
  #   model_command: "ollama run llama3.1"
  #   model_command: "ollama run qwen2.5"
  #
  # The command must be resolvable via PATH; the whole prompt is sent in one
  # call (timeout 120s). If empty, narrative falls back to templates and the
  # AI validation passes are skipped.
  model_command: ""
  api_key: ""                # reserved for future remote providers

  validate: false            # FP validation: rule-based checks always run;
                             # set this to also run the AI verifier + devil's
                             # advocate passes (requires model_command).
  devil_advocate: true       # Pass-2: try to DISPROVE findings that survive
                             # the AI verifier.
  fp_threshold: 0.65         # findings with confidence below this after AI
                             # review are treated as likely false positives.
  validate_scope: high       # high | medium | all - only findings at/above
                             # this severity receive AI validation.
  validate_limit: 200        # cap on how many top-priority findings get AI
                             # validation per run.

validation:
  strict: false              # FP reduction: default only provable signals
                             # (constant-bound indices, ambient-only taint,
                             # constant formats, consumed return values, ...).
                             # Set to true to ALSO demote findings that have no
                             # attacker-relevant provenance at all (more
                             # aggressive, may hide a few true positives).

timeout: 300                 # seconds per analyzer
max_memory_mb: 2048
parallel_analyzers: true
log_level: INFO
"""


def _coerce(value: str):
    """Parse a CLI string into a YAML-friendly scalar."""
    low = value.strip().lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "none", "~", ""):
        return None
    if low.startswith(("[", "{")):  # inline list/dict via YAML
        try:
            return yaml.safe_load(value)
        except yaml.YAMLError:
            return value
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _set_nested(root: dict, parts: list[str], value) -> None:
    """Set a dotted key like ``ai.validate_limit`` inside ``root`` dict."""
    node = root
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = value


def _get_nested(root: dict, parts: list[str]):
    node: object = root
    for part in parts:
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _as_plain(value):
    """Convert dataclass config (enums/dataclasses) into plain YAML data."""
    if is_dataclass(value):
        return {k: _as_plain(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {k: _as_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_as_plain(v) for v in value]
    if hasattr(value, "value"):  # enum
        return value.value
    return value


@config_app.command("init")
def config_init(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite an existing vra.yaml"),
    path: str = typer.Option(str(_DEFAULT_CONFIG_PATH), "--path", help="Where to write the template"),
):
    """Generate a commented vra.yaml template in the current directory."""
    target = Path(path)
    if target.exists() and not force:
        console.print(
            f"[yellow]{target} already exists. Use --force to overwrite.[/yellow]"
        )
        raise typer.Exit(1)
    target.write_text(VRA_CONFIG_TEMPLATE, encoding="utf-8")
    console.print(f"[green]Configuration template written to {target}[/green]")
    console.print(
        "[dim]Next: edit it (e.g. `vra config set ai.model_command \"ollama run llama3.1\"`).[/dim]"
    )


@config_app.command("show")
def config_show(
    section: str = typer.Option(None, "--section", "-s", help="Limit output to a section: ai, analyzers, rules, ..."),
    path: str = typer.Option(str(_DEFAULT_CONFIG_PATH), "--path", help="Config file to read"),
):
    """Show the effective configuration (defaults merged with vra.yaml)."""
    config_path = Path(path)
    if not config_path.exists():
        console.print(f"[dim]No {config_path} found; showing built-in defaults.[/dim]")
    config = load_config(config_path if config_path.exists() else None)
    data = _as_plain(config)

    if section:
        if section not in data:
            console.print(f"[red]Unknown section: {section}[/red]")
            console.print(f"[dim]Available sections: {', '.join(data.keys())}[/dim]")
            raise typer.Exit(1)
        data = {section: data[section]}

    console.print(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), end="")
    console.print(
        f"\n[dim]Loaded from: {config_path.resolve() if config_path.exists() else '(built-in defaults)'}[/dim]"
    )
    console.print(
        "[dim]Edit inline with: `vra config set ai.model_command \"ollama run llama3.1\"`[/dim]"
    )


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Dotted key, e.g. ai.model_command or ai.enabled"),
    value: str = typer.Argument(..., help="New value (true/false, number, or string)"),
    path: str = typer.Option(str(_DEFAULT_CONFIG_PATH), "--path", help="Config file to edit"),
):
    """Set a configuration value in vra.yaml (creates the file if needed).

    Note: the file is rewritten via YAML round-trip, so comments outside the
    value being changed are not preserved. Re-run `vra config init --force` to
    recover the commented template.
    """
    target = Path(path)
    if target.exists():
        try:
            data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            console.print(f"[red]Failed to parse {target}: {e}[/red]")
            raise typer.Exit(1)
    else:
        data = {}

    parts = [p.strip() for p in key.split(".") if p.strip()]
    if not parts:
        console.print("[red]Invalid key[/red]")
        raise typer.Exit(1)

    coerced = _coerce(value)
    _set_nested(data, parts, coerced)
    target.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False),
        encoding="utf-8",
    )
    shown = _as_plain(_get_nested(data, parts))
    console.print(f"[green]Set {key} = {shown!r} in {target}[/green]")
    console.print(f"[dim]Verify with: `vra config show --section {parts[0]}`[/dim]")


@config_app.command("unset")
def config_unset(
    key: str = typer.Argument(..., help="Dotted key to remove, e.g. ai.api_key"),
    path: str = typer.Option(str(_DEFAULT_CONFIG_PATH), "--path", help="Config file to edit"),
):
    """Remove a key from vra.yaml."""
    target = Path(path)
    if not target.exists():
        console.print(f"[yellow]{target} does not exist; nothing to unset.[/yellow]")
        raise typer.Exit(0)
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        console.print(f"[red]Failed to parse {target}: {e}[/red]")
        raise typer.Exit(1)

    parts = [p.strip() for p in key.split(".") if p.strip()]
    node = data
    for part in parts[:-1]:
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            console.print(f"[yellow]Key not found: {key}[/yellow]")
            raise typer.Exit(0)
    if isinstance(node, dict) and parts[-1] in node:
        del node[parts[-1]]
        target.write_text(
            yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False),
            encoding="utf-8",
        )
        console.print(f"[green]Removed {key} from {target}[/green]")
    else:
        console.print(f"[yellow]Key not found: {key}[/yellow]")


def config_doctor() -> None:
    """Small hint printed from `vra doctor` about the local model check."""
    console.print("[bold]AI model:[/bold]")
    try:
        cfg_path = _DEFAULT_CONFIG_PATH
        config = load_config(cfg_path if cfg_path.exists() else None)
        command = (config.ai.model_command or "").strip()
        if not command:
            console.print("  [yellow]not configured[/yellow] - set `ai.model_command` (e.g. \"ollama run llama3.1\")")
            return
        import shutil

        binary = shutil.which(command.split()[0])
        if binary:
            console.print(f"  [green]found: {binary}[/green] - AI validation & narratives will run their LLM passes")
        else:
            console.print(f"  [red]model command not on PATH: {command}[/red]")
    except Exception as e:  # pragma: no cover - defensive
        console.print(f"  [dim]model check skipped: {e}[/dim]")
