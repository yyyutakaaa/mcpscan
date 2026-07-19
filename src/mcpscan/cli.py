"""mcpscan command-line interface."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from typer.core import TyperGroup

from mcpscan import __version__
from mcpscan.engine import scan as run_scan
from mcpscan.engine import worst_severity_met
from mcpscan.models import Severity
from mcpscan.reporters import json_reporter, sarif_reporter, terminal
from mcpscan.rules import RuleSet


class _DefaultScanGroup(TyperGroup):
    """Route `mcpscan PATH [...]` to the scan command so no subcommand is needed."""

    def parse_args(self, ctx: typer.Context, args: list[str]) -> list[str]:
        if args and args[0] not in self.commands and args[0] not in ("--help", "--version"):
            args = ["scan", *args]
        return super().parse_args(ctx, args)


app = typer.Typer(
    cls=_DefaultScanGroup,
    add_completion=False,
    no_args_is_help=True,
    help="Static security scanner for MCP servers and AI agent skills.",
)


class Format(str, Enum):
    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mcpscan {__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Static security scanner for MCP servers and AI agent skills."""


@app.command("scan")
def scan_command(
    path: Path = typer.Argument(..., help="File or directory to scan."),
    format: Format = typer.Option(Format.TERMINAL, "--format", help="Report format."),
    output: Optional[Path] = typer.Option(
        None, "--output", help="Write the report to a file instead of stdout."
    ),
    fail_on: Severity = typer.Option(
        Severity.HIGH,
        "--fail-on",
        help="Exit 1 when findings at or above this severity exist.",
    ),
    rules_dir: Optional[Path] = typer.Option(
        None, "--rules", help="Additional custom YAML rules directory."
    ),
    exclude: list[str] = typer.Option(
        [], "--exclude", help="Glob pattern to exclude (repeatable)."
    ),
) -> None:
    """Scan a file or directory for MCP security issues."""
    if not path.exists():
        typer.secho(f"Error: path does not exist: {path}", fg="red", err=True)
        raise typer.Exit(2)

    try:
        result = run_scan(path, [rules_dir] if rules_dir else None, list(exclude))
    except (OSError, ValueError) as exc:
        typer.secho(f"Error: {exc}", fg="red", err=True)
        raise typer.Exit(2) from exc

    if format is Format.TERMINAL:
        if output is not None:
            with output.open("w", encoding="utf-8") as handle:
                terminal.render(result, path, Console(file=handle, force_terminal=False))
        else:
            terminal.render(result, path)
    else:
        renderer = json_reporter if format is Format.JSON else sarif_reporter
        report = renderer.render(result)
        if output is not None:
            output.write_text(report + "\n", encoding="utf-8")
        else:
            typer.echo(report)

    raise typer.Exit(1 if worst_severity_met(result, fail_on) else 0)


@app.command("rules")
def list_rules(
    rules_dir: Optional[Path] = typer.Option(
        None, "--rules", help="Additional custom YAML rules directory."
    ),
) -> None:
    """List all loaded rules."""
    try:
        ruleset = RuleSet.load([rules_dir] if rules_dir else None)
    except (OSError, ValueError) as exc:
        typer.secho(f"Error: {exc}", fg="red", err=True)
        raise typer.Exit(2) from exc

    table = Table(title=f"mcpscan v{__version__} — loaded rules", header_style="bold")
    table.add_column("ID", style="bold")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Title")
    for info in ruleset.rule_infos():
        style = terminal.SEVERITY_STYLE[info.severity]
        table.add_row(
            info.id,
            f"[{style}]{info.severity.value}[/{style}]",
            info.category.value,
            info.title,
        )
    Console().print(table)


if __name__ == "__main__":
    app()
