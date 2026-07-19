"""Rich terminal reporter — the face of mcpscan."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcpscan import __version__
from mcpscan.models import Finding, ScanResult, Severity

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "grey62",
}

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _finding_panel(finding: Finding) -> Panel:
    style = SEVERITY_STYLE[finding.severity]
    loc = str(finding.location.file)
    if finding.location.line is not None:
        loc += f":{finding.location.line}"

    body: list[Text] = [Text(loc, style="bold white")]
    body.append(Text(finding.description, style="default"))
    if finding.location.snippet:
        body.append(Text(f"  {finding.location.snippet}", style="dim"))
    if finding.remediation:
        body.append(Text(f"fix: {finding.remediation}", style="green"))

    title = Text.assemble(
        (f" {finding.severity.value.upper()} ", f"reverse {style}"),
        " ",
        (finding.rule_id, "bold"),
        "  ",
        (finding.title, style),
    )
    return Panel(Group(*body), title=title, title_align="left", border_style=style)


def _summary_table(result: ScanResult) -> Table:
    table = Table(title="Summary", show_edge=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Findings", justify="right")
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in result.findings:
        counts[finding.severity] += 1
    for sev in SEVERITY_ORDER:
        style = SEVERITY_STYLE[sev]
        table.add_row(Text(sev.value, style=style), str(counts[sev]))
    return table


def render(result: ScanResult, target: Path, console: Console | None = None) -> None:
    console = console or Console()
    console.print()
    console.print(
        Panel(
            Text.assemble(
                ("mcpscan ", "bold magenta"),
                (f"v{__version__}", "magenta"),
                ("  •  scanning ", "default"),
                (str(target), "bold"),
            ),
            border_style="magenta",
        )
    )

    findings = sorted(result.findings, key=lambda f: (-f.severity.rank, str(f.location.file)))
    for finding in findings:
        console.print(_finding_panel(finding))

    console.print()
    console.print(_summary_table(result))
    console.print(
        f"[dim]{result.targets_scanned} target(s) scanned in {result.duration_ms} ms[/dim]"
    )

    if not result.findings:
        console.print("[bold green]✓ No issues found.[/bold green]")
    else:
        worst = max(result.findings, key=lambda f: f.severity.rank).severity
        style = SEVERITY_STYLE[worst]
        console.print(
            Text.assemble(
                ("✗ ", style),
                (f"{len(result.findings)} finding(s), worst severity: ", "default"),
                (worst.value, f"bold {style}"),
            )
        )
