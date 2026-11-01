"""Terminal table and summary rendering using Rich."""

from __future__ import annotations

import io

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_web_auditor.models import BatchResult, ScanResult, Severity

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "dim white",
}

GRADE_STYLES: dict[str, str] = {
    "A+": "bold green",
    "A": "green",
    "B": "bold blue",
    "C": "bold yellow",
    "D": "bold magenta",
    "F": "bold red",
}


def _get_score_style(score: int) -> str:
    if score >= 85:
        return "bold green"
    if score >= 70:
        return "bold blue"
    if score >= 50:
        return "bold yellow"
    return "bold red"


def render_scan_table(result: ScanResult, console: Console | None = None) -> str:
    """Render a single target's scan result to Rich console or return formatted string."""
    output_buffer = io.StringIO()
    target_console = console or Console(file=output_buffer, force_terminal=False, width=110)

    # Header Panel
    score_style = _get_score_style(result.score)
    grade_style = GRADE_STYLES.get(result.grade, "bold")

    meta_text = Text()
    meta_text.append("Target URL:   ", style="bold")
    meta_text.append(f"{result.target_url}\n")
    meta_text.append("Final URL:    ", style="bold")
    meta_text.append(f"{result.final_url}\n")
    meta_text.append("Status Code:  ", style="bold")
    meta_text.append(f"{result.status_code}\n")
    meta_text.append("Latency:      ", style="bold")
    meta_text.append(f"{result.response_time_ms:.1f} ms\n")
    meta_text.append("Security Score: ", style="bold")
    meta_text.append(f"{result.score}/100", style=score_style)
    meta_text.append("  |  Grade: ", style="bold")
    meta_text.append(f"[{result.grade}]", style=grade_style)

    if result.error:
        meta_text.append(f"\nScan Error:   {result.error}", style="bold red")

    panel = Panel(
        meta_text,
        title="[bold blue]Logihertz Defensive Web Auditor - Audit Report[/bold blue]",
        border_style="blue",
        padding=(1, 2),
    )
    target_console.print(panel)

    # Findings Table
    findings_table = Table(
        title=f"Findings & Recommendations ({len(result.findings)} detected)",
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )
    findings_table.add_column("Severity", justify="center", width=12)
    findings_table.add_column("ID", style="dim", width=26)
    findings_table.add_column("Title & Evidence", ratio=3)
    findings_table.add_column("Remediation", ratio=2)

    if not result.findings:
        findings_table.add_row(
            "[bold green]PASS[/bold green]",
            "-",
            "No security policy misconfigurations detected.",
            "Maintain current security posture.",
        )
    else:
        for f in result.findings:
            sev_badge = Text(f.severity.value, style=SEVERITY_STYLES.get(f.severity, "white"))
            content = Text()
            content.append(f"{f.title}\n", style="bold")
            content.append(f"Evidence: {f.evidence}\n", style="italic")
            if f.cwe_id:
                content.append(f"Ref: {f.cwe_id}", style="dim")

            remediation = Text(f.recommendation)
            findings_table.add_row(sev_badge, f.id, content, remediation)

    target_console.print(findings_table)

    # Cookies Table if cookies exist
    if result.cookies:
        cookie_table = Table(
            title="Set-Cookie Security Attributes",
            show_header=True,
            header_style="bold cyan",
            expand=True,
        )
        cookie_table.add_column("Cookie Name", style="bold", ratio=2)
        cookie_table.add_column("Secure", justify="center", width=10)
        cookie_table.add_column("HttpOnly", justify="center", width=10)
        cookie_table.add_column("SameSite", justify="center", width=12)
        cookie_table.add_column("Domain / Path", style="dim", ratio=2)

        for c in result.cookies:
            sec_text = "[green]YES[/green]" if c.secure else "[red]NO[/red]"
            http_text = "[green]YES[/green]" if c.httponly else "[yellow]NO[/yellow]"
            ss_text = f"[cyan]{c.samesite}[/cyan]" if c.samesite else "[red]NONE[/red]"
            dom_path = f"{c.domain or '*'} | {c.path or '/'}"
            cookie_table.add_row(c.name, sec_text, http_text, ss_text, dom_path)

        target_console.print(cookie_table)

    # CORS Probe Summary
    if result.cors and result.cors.allow_origin:
        cors_table = Table(
            title="CORS Probe Details",
            show_header=True,
            header_style="bold yellow",
            expand=True,
        )
        cors_table.add_column("Probed Origin", ratio=2)
        cors_table.add_column("Access-Control-Allow-Origin", ratio=2)
        cors_table.add_column("Allow-Credentials", justify="center", width=18)
        cors_table.add_column("Vulnerable", justify="center", width=12)

        is_vuln_text = (
            "[bold red]YES[/bold red]" if result.cors.is_vulnerable else "[green]NO[/green]"
        )
        acac_text = "[red]true[/red]" if result.cors.allow_credentials else "[dim]false[/dim]"
        cors_table.add_row(
            result.cors.tested_origin,
            result.cors.allow_origin or "None",
            acac_text,
            is_vuln_text,
        )
        target_console.print(cors_table)

    return output_buffer.getvalue()


def render_batch_table(batch: BatchResult, console: Console | None = None) -> str:
    """Render batch audit summary to Rich console or return formatted string."""
    output_buffer = io.StringIO()
    target_console = console or Console(file=output_buffer, force_terminal=False, width=120)

    # Batch summary header
    avg_score = batch.average_score
    score_style = _get_score_style(int(avg_score))

    summary_text = Text()
    summary_text.append(f"Total Targets Scanned: {batch.total_scanned}\n", style="bold")
    summary_text.append("Average Security Score: ", style="bold")
    summary_text.append(f"{avg_score:.1f}/100\n", style=score_style)
    summary_text.append(f"Completed At: {batch.timestamp}", style="dim")

    panel = Panel(
        summary_text,
        title="[bold blue]Batch Security Audit Summary - Logihertz Web Auditor[/bold blue]",
        border_style="blue",
        padding=(1, 2),
    )
    target_console.print(panel)

    table = Table(
        title="Audited Targets Overview",
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Target URL", ratio=3)
    table.add_column("Status", justify="center", width=8)
    table.add_column("Score", justify="center", width=8)
    table.add_column("Grade", justify="center", width=8)
    table.add_column("Crit / High / Med / Low", justify="center", width=24)
    table.add_column("Latency", justify="right", width=12)

    for r in batch.results:
        sc_style = _get_score_style(r.score)
        gr_style = GRADE_STYLES.get(r.grade, "bold")
        counts = r.severity_counts
        counts_str = (
            f"[bold red]{counts['CRITICAL']}[/bold red] / "
            f"[red]{counts['HIGH']}[/red] / "
            f"[yellow]{counts['MEDIUM']}[/yellow] / "
            f"[cyan]{counts['LOW']}[/cyan]"
        )

        if r.status_code in (200, 301, 302):
            status_str = f"[green]{r.status_code}[/green]"
        else:
            status_str = f"[red]{r.status_code}[/red]"

        if r.error:
            status_str = "[bold red]ERR[/bold red]"

        table.add_row(
            r.target_url,
            status_str,
            f"[{sc_style}]{r.score}[/{sc_style}]",
            f"[{gr_style}]{r.grade}[/{gr_style}]",
            counts_str,
            f"{r.response_time_ms:.1f} ms",
        )

    target_console.print(table)
    return output_buffer.getvalue()
