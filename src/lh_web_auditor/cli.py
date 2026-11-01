"""Command-line interface (CLI) for lh-web-auditor."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from lh_web_auditor import __author__, __version__
from lh_web_auditor.exporters.json_export import export_batch_json, export_scan_json
from lh_web_auditor.exporters.sarif import export_batch_sarif, export_scan_sarif
from lh_web_auditor.exporters.table import render_batch_table, render_scan_table
from lh_web_auditor.models import Format
from lh_web_auditor.scanner import WebAuditor

app = typer.Typer(
    name="lh-auditor",
    help=(
        "Asynchronous defensive web configuration auditor developed by "
        "Logihertz Systems OPC Pvt Ltd."
    ),
    add_completion=False,
)

console = Console()


def version_callback(value: bool) -> None:
    """Print the application version and exit."""
    if value:
        typer.echo(f"lh-auditor v{__version__} - {__author__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Display version information and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Entry point callback for global options."""


@app.command(name="scan")
def scan_command(
    url: str = typer.Argument(
        ...,
        help="Target URL to inspect (e.g. https://example.com)",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        "-t",
        help="Network request timeout in seconds.",
    ),
    format_type: Format = typer.Option(
        Format.TABLE,
        "--format",
        "-f",
        case_sensitive=False,
        help="Output format (table, json, sarif).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="File path to write output report.",
    ),
    user_agent: str = typer.Option(
        f"lh-web-auditor/{__version__}",
        "--user-agent",
        help="Custom HTTP User-Agent header.",
    ),
    follow_redirects: bool = typer.Option(
        True,
        "--follow-redirects/--no-follow-redirects",
        help="Follow HTTP redirects during audit.",
    ),
    verify_ssl: bool = typer.Option(
        True,
        "--verify-ssl/--no-verify-ssl",
        help="Verify SSL/TLS certificates.",
    ),
) -> None:
    """Audit security headers, cookies, CORS, and transport settings for a single URL."""
    auditor = WebAuditor(
        timeout=timeout,
        user_agent=user_agent,
        follow_redirects=follow_redirects,
        verify_ssl=verify_ssl,
    )

    result = asyncio.run(auditor.scan(url))

    if format_type == Format.TABLE:
        table_output = render_scan_table(result, console=None if output else console)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(table_output, encoding="utf-8")
            console.print(f"[bold green]Table report saved to:[/bold green] {output}")
    elif format_type == Format.JSON:
        json_output = export_scan_json(result)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json_output, encoding="utf-8")
            console.print(f"[bold green]JSON report saved to:[/bold green] {output}")
        else:
            typer.echo(json_output)
    elif format_type == Format.SARIF:
        sarif_output = export_scan_sarif(result)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(sarif_output, encoding="utf-8")
            console.print(f"[bold green]SARIF report saved to:[/bold green] {output}")
        else:
            typer.echo(sarif_output)


@app.command(name="batch")
def batch_command(
    file: Path = typer.Argument(
        ...,
        help="Text file containing target URLs (one per line).",
        exists=True,
        readable=True,
    ),
    concurrency: int = typer.Option(
        5,
        "--concurrency",
        "-c",
        help="Maximum concurrent scan tasks.",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        "-t",
        help="Network request timeout in seconds.",
    ),
    format_type: Format = typer.Option(
        Format.JSON,
        "--format",
        "-f",
        case_sensitive=False,
        help="Output format (table, json, sarif).",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="File path to write batch report.",
    ),
    user_agent: str = typer.Option(
        f"lh-web-auditor/{__version__}",
        "--user-agent",
        help="Custom HTTP User-Agent header.",
    ),
    follow_redirects: bool = typer.Option(
        True,
        "--follow-redirects/--no-follow-redirects",
        help="Follow HTTP redirects during audit.",
    ),
    verify_ssl: bool = typer.Option(
        True,
        "--verify-ssl/--no-verify-ssl",
        help="Verify SSL/TLS certificates.",
    ),
) -> None:
    """Audit a list of URLs concurrently from a text file."""
    lines = file.read_text(encoding="utf-8").splitlines()
    urls = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]

    if not urls:
        console.print("[yellow]Warning:[/yellow] No valid URLs found in target file.")
        raise typer.Exit(code=1)

    auditor = WebAuditor(
        timeout=timeout,
        user_agent=user_agent,
        follow_redirects=follow_redirects,
        verify_ssl=verify_ssl,
    )

    batch_result = asyncio.run(auditor.scan_batch(urls, concurrency=concurrency))

    if format_type == Format.TABLE:
        table_output = render_batch_table(batch_result, console=None if output else console)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(table_output, encoding="utf-8")
            console.print(f"[bold green]Batch table report saved to:[/bold green] {output}")
    elif format_type == Format.JSON:
        json_output = export_batch_json(batch_result)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json_output, encoding="utf-8")
            console.print(f"[bold green]Batch JSON report saved to:[/bold green] {output}")
        else:
            typer.echo(json_output)
    elif format_type == Format.SARIF:
        sarif_output = export_batch_sarif(batch_result)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(sarif_output, encoding="utf-8")
            console.print(f"[bold green]Batch SARIF report saved to:[/bold green] {output}")
        else:
            typer.echo(sarif_output)


if __name__ == "__main__":
    app()
