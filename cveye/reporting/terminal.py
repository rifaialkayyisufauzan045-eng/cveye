"""Terminal (console) output formatter."""

from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.table import Table

from cveye.scan import ScanResult

console = Console()


def print_scan_result(result: ScanResult, quiet: bool = False) -> None:
    """Print full scan results to terminal."""
    if quiet:
        return

    # Target header
    console.rule(f"[bold cyan]CVEye Scan: {result.target}[/bold cyan]")

    # IP
    if result.ip:
        console.print(f"[dim]IP: {result.ip}[/dim]")
    console.print()

    # Open ports
    if result.ports:
        console.print("[bold]OPEN PORTS[/bold]")
        console.print("─" * 40)
        table = Table(show_header=True, header_style="bold")
        table.add_column("Port", style="cyan", width=8)
        table.add_column("Protocol", width=8)
        table.add_column("Service", width=12)
        table.add_column("Version", width=20)
        table.add_column("Confidence", width=12)

        for port in result.ports:
            table.add_row(
                str(port.port),
                port.protocol,
                port.service or "unknown",
                port.version or "",
                port.confidence.value if port.confidence else "",
            )
        console.print(table)
        console.print()

    # Web technologies
    if result.web_result and result.web_result.technologies:
        console.print("[bold]WEB TECHNOLOGY[/bold]")
        console.print("─" * 40)
        for tech in result.web_result.technologies:
            ver = f" [dim]{tech.version}[/dim]" if tech.version else ""
            conf = f" ([dim]{tech.confidence.value}[/dim])" if tech.confidence else ""
            console.print(f"  [green]{tech.name}[/green]{ver}{conf}")
        console.print()

    # WordPress plugins/themes
    if result.web_result:
        if result.web_result.plugins:
            console.print("[bold]WORDPRESS PLUGINS[/bold]")
            console.print("─" * 40)
            for plugin in result.web_result.plugins:
                ver = f" [dim]{plugin.version}[/dim]" if plugin.version else ""
                console.print(f"  [blue]{plugin.name}[/blue]{ver}")
            console.print()

        if result.web_result.themes:
            console.print("[bold]WORDPRESS THEMES[/bold]")
            console.print("─" * 40)
            for theme in result.web_result.themes:
                console.print(f"  [blue]{theme.name}[/blue]")
            console.print()

    # Security headers
    if result.web_result and result.web_result.security_headers:
        console.print("[bold]SECURITY HEADERS[/bold]")
        console.print("─" * 40)
        for h in result.web_result.security_headers:
            icon = "[green]✓[/green]" if h.present else "[red]✗[/red]"
            console.print(f"  {icon} {h.name}")
        console.print()

    # TLS
    if result.web_result and result.web_result.tls:
        tls = result.web_result.tls
        console.print("[bold]TLS[/bold]")
        console.print("─" * 40)
        if tls.protocol:
            console.print(f"  Protocol     : {tls.protocol}")
        if tls.subject:
            console.print(f"  Subject      : {tls.subject}")
        if tls.issuer:
            console.print(f"  Issuer       : {tls.issuer}")
        if tls.valid_until:
            console.print(f"  Valid Until  : {tls.valid_until}")
        if tls.days_remaining is not None:
            color = "green" if tls.days_remaining > 30 else "red"
            console.print(f"  Days Remaining: [{color}]{tls.days_remaining}[/{color}]")
        console.print(f"  Status       : {tls.status}")
        console.print()

    # CVE Intelligence
    if result.cve_intelligence:
        from cveye.reporting.cve_output import print_cve_search_terminal_output

        print_cve_search_terminal_output(result.cve_intelligence)
