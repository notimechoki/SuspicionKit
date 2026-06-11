from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from suspicionkit import __version__
from suspicionkit.core.analyzer import analyze_url
from suspicionkit.renderer import render_report
from suspicionkit.reports import report_to_json, write_text_file

app = typer.Typer(
    name="suspicionkit",
    help="Terminal-first threat analysis toolkit.",
    add_completion=False,
    invoke_without_command=True,
)

console = Console()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit.",
        is_eager=True,
    ),
) -> None:
    if version:
        console.print(f"SuspicionKit [bold green]{__version__}[/bold green]")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit()


@app.command("url")
def check_url(
    url: str = typer.Argument(..., help="URL to analyze."),
    no_network: bool = typer.Option(
        False,
        "--no-network",
        help="Disable DNS/HTTP/WHOIS/TLS/content checks.",
    ),
    no_content: bool = typer.Option(
        False,
        "--no-content",
        help="Disable HTML body inspection but keep DNS/HTTP/WHOIS/TLS checks.",
    ),
    timeout: float = typer.Option(
        7.0,
        "--timeout",
        min=1.0,
        max=30.0,
        help="Network timeout in seconds.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Print a machine-readable JSON report instead of the Rich terminal report.",
    ),
    output_path: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write JSON report to a file. Requires --json.",
        file_okay=True,
        dir_okay=False,
        writable=True,
        resolve_path=True,
    ),
) -> None:
    if output_path and not json_output:
        console.print("[red]Error:[/red] --output is currently supported with --json only.")
        raise typer.Exit(code=1)

    try:
        report = analyze_url(
            url,
            no_network=no_network,
            timeout=timeout,
            inspect_content=not no_content,
        )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if json_output:
        json_text = report_to_json(report)

        if output_path:
            write_text_file(output_path, json_text + "\n")
            console.print(f"[green]JSON report written to:[/green] {output_path}")
            return

        typer.echo(json_text)
        return

    render_report(report)