from __future__ import annotations

import typer
from rich.console import Console

from suspicionkit import __version__
from suspicionkit.core.analyzer import analyze_url
from suspicionkit.renderer import render_report

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
) -> None:
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

    render_report(report)