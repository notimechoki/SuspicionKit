from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from suspicionkit.models import RiskLevel, UrlReport


def render_report(report: UrlReport) -> None:
    console = Console()

    color = _risk_color(report.risk_level)
    title = Text("SuspicionKit URL Report", style=f"bold {color}")

    console.print()
    console.print(Panel(title, subtitle="v0.0.1", box=box.ROUNDED, border_style=color))

    console.print(f"[bold]Original:[/bold]   {report.original_url}")
    console.print(f"[bold]Normalized:[/bold] {report.normalized_url}")
    console.print(f"[bold]Domain:[/bold]     {report.domain}")
    console.print(f"[bold]Root domain:[/bold] {report.registered_domain}")
    console.print()

    score_text = Text(f"Risk score: {report.score}/100", style=f"bold {color}")
    console.print(score_text)
    console.print(ProgressBar(total=100, completed=report.score, width=50, pulse=False))
    console.print(f"Risk level: [{color} bold]{report.risk_level.value.upper()}[/{color} bold]")
    console.print()

    table = Table(title="Checks", box=box.SIMPLE_HEAVY)
    table.add_column("Status", style="bold")
    table.add_column("Check")
    table.add_column("Details")
    table.add_column("Δ", justify="right")

    for check in report.checks:
        table.add_row(
            _status_label(check.status),
            check.name,
            check.details,
            str(check.score_delta),
        )

    console.print(table)

    if report.notes:
        console.print()
        console.print(Panel("\n".join(report.notes), title="Notes", border_style="blue"))

    if report.warnings:
        console.print()
        console.print(Panel("\n".join(report.warnings), title="Important", border_style="yellow"))

    console.print()


def _risk_color(level: RiskLevel) -> str:
    if level == RiskLevel.LOW:
        return "green"
    if level == RiskLevel.MEDIUM:
        return "yellow"
    if level == RiskLevel.HIGH:
        return "red"

    return "bright_red"


def _status_label(status: str) -> str:
    labels = {
        "ok": "[green]OK[/green]",
        "info": "[blue]INFO[/blue]",
        "popular": "[green]POPULAR[/green]",
        "unknown": "[yellow]UNKNOWN[/yellow]",
        "warning": "[yellow]WARN[/yellow]",
        "danger": "[red]DANGER[/red]",
        "skipped": "[dim]SKIPPED[/dim]",
    }

    return labels.get(status, status.upper())