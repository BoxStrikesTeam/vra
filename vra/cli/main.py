"""Main CLI entry point for VRA."""

from __future__ import annotations

import typer

from vra.cli.ai_command import ai_app
from vra.cli.commands import (
    analyze_command,
    analyzer_app,
    clean_command,
    doctor_command,
    finding_app,
    findings_command,
    init_command,
    inspect_command,
    report_command,
    rule_app,
    test_command,
)
from vra.cli.config_command import config_app
from vra.cli.ui import print_banner

app = typer.Typer(
    name="vra",
    help="VRA - Vulnerability Research Automation",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main(ctx: typer.Context):
    """VRA - C/C++ Automated Vulnerability Research Workbench."""
    print_banner()


app.command("init")(init_command)
app.command("inspect")(inspect_command)
app.command("analyze")(analyze_command)
app.command("findings")(findings_command)
app.command("report")(report_command)
app.add_typer(finding_app, name="finding")
app.add_typer(rule_app, name="rule")
app.add_typer(analyzer_app, name="analyzer")
app.add_typer(config_app, name="config")
app.add_typer(ai_app, name="ai")
app.command("doctor")(doctor_command)
app.command("clean")(clean_command)
app.command("test")(test_command)


def run():
    app()


if __name__ == "__main__":
    run()
