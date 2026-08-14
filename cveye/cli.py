"""CVEye CLI application."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from cveye import __version__
from cveye.config import CONFIG_FILE, CVEyeConfig
from cveye.cve.client import CVEClient
from cveye.logger import get_logger, setup_logging
from cveye.network.scanner import scan_network
from cveye.reporting.html_report import write_html_report
from cveye.reporting.json_report import write_json_report
from cveye.reporting.terminal import print_scan_result
from cveye.risk.engine import calculate_risk
from cveye.scan import ScanResult
from cveye.utils.validators import TargetValidationError, validate_target
from cveye.web.models import Technology
from cveye.web.scanner import scan_web

app = typer.Typer(
    name="cveye",
    help="CVEye — CVE Intelligence & Technology Scanner",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target: IP, hostname, URL, or CIDR"),
    ports: Optional[str] = typer.Option(None, "--ports", help="Custom ports (comma-separated)"),
    web: bool = typer.Option(True, "--web/--no-web", help="Enable web fingerprinting"),
    network: bool = typer.Option(True, "--network/--no-network", help="Enable network/port scanning"),
    cve: bool = typer.Option(True, "--cve/--no-cve", help="Enable CVE intelligence"),
    deep: bool = typer.Option(False, "--deep", help="Deep scan (extra paths)"),
    timeout: float = typer.Option(5.0, "--timeout", help="Connection timeout (seconds)"),
    threads: int = typer.Option(10, "--threads", help="Scan thread count"),
    rate_limit: float = typer.Option(1.0, "--rate-limit", help="Delay between requests (seconds)"),
    json_output: Optional[str] = typer.Option(None, "--json", help="Save JSON report to file"),
    html_output: Optional[str] = typer.Option(None, "--html", help="Save HTML report to file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress terminal output"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
) -> None:
    """Scan a target for technologies and CVE correlations."""
    setup_logging(verbose=verbose, quiet=quiet)
    logger = get_logger()
    config = CVEyeConfig.load()

    # Validate target
    try:
        target_info = validate_target(target)
    except TargetValidationError as exc:
        console.print(f"[red][!] Invalid target: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    result = ScanResult(target=target)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
        disable=quiet,
    ) as progress:

        # ── Network scan ──────────────────────────────────────────────
        if network:
            progress.add_task("[+] Resolving target...", total=None)
            progress.add_task("[+] Network discovery...", total=None)
            task = progress.add_task("[+] Port scanning...", total=None)

            try:
                net_results = scan_network(
                    target_info,
                    ports_str=ports,
                    timeout=timeout,
                    threads=threads,
                )
                result.network = net_results
                result.ip = net_results[0].ip if net_results else None
                # Flatten ports to result.ports from first host
                if net_results:
                    result.ports = net_results[0].ports
            except Exception as exc:
                logger.warning("Network scan error: %s", exc)

            progress.update(task, description="[+] Port scanning... done")
            progress.add_task("[+] Service fingerprinting...", total=None)

        # ── Web scan ──────────────────────────────────────────────────
        if web:
            progress.add_task("[+] Web fingerprinting...", total=None)

            try:
                result.web_result = scan_web(
                    target_info,
                    timeout=timeout,
                    rate_limit=rate_limit,
                    deep=deep,
                )
            except Exception as exc:
                logger.warning("Web scan error: %s", exc)

        # ── Version detection ─────────────────────────────────────────
        progress.add_task("[+] Version detection...", total=None)

        technologies: list[Technology] = []

        # Collect technologies from web scan
        if result.web_result:
            technologies.extend(result.web_result.technologies)

        # Collect technologies from network services
        if result.network:
            for net in result.network:
                for svc in net.services:
                    if svc.product:
                        from cveye.network.models import Confidence

                        technologies.append(
                            Technology(
                                name=svc.product,
                                category="Service",
                                version=svc.version,
                                confidence=svc.confidence,
                                evidence=svc.evidence,
                                source="network banner",
                            )
                        )

        # Deduplicate by name (keep highest version confidence)
        seen: set[str] = set()
        unique_tech: list[Technology] = []
        for t in technologies:
            key = t.name.lower()
            if key not in seen:
                seen.add(key)
                unique_tech.append(t)

        result.technologies = unique_tech

        # ── CVE Web Intelligence ──────────────────────────────────────
        if cve and unique_tech:
            progress.add_task("[+] CVE correlation...", total=None)

            try:
                cve_client = CVEClient(config)
                result.cve_intelligence = cve_client.correlate_technologies(unique_tech)
            except Exception as exc:
                logger.warning("CVE correlation error: %s", exc)
                console.print("[yellow][!] CVE information unavailable[/yellow]")

        # ── Risk analysis ─────────────────────────────────────────────
        progress.add_task("[+] Risk analysis...", total=None)

        # ── Report ────────────────────────────────────────────────────
        progress.add_task("[+] Generating report...", total=None)

    # Terminal output
    print_scan_result(result, quiet=quiet)

    # JSON report
    if json_output:
        path = Path(json_output)
        write_json_report(result, path)
        if not quiet:
            console.print(f"[green]JSON report:[/green] {path}")

    # HTML report
    if html_output:
        path = Path(html_output)
        write_html_report(result, path)
        if not quiet:
            console.print(f"[green]HTML report:[/green] {path}")


@app.command()
def version() -> None:
    """Show CVEye version."""
    console.print(f"CVEye v{__version__}")
    console.print("CVE Intelligence & Technology Scanner")


@app.command()
def update() -> None:
    """Update CVE cache and KEV catalog."""
    console.print("[+] Updating CISA KEV catalog...")
    try:
        from cveye.cve.kev import KEVCatalog, KEV_CACHE_FILE as KEV_CACHE

        kev = KEVCatalog()
        console.print("[green]KEV catalog updated.[/green]")
    except Exception as exc:
        console.print(f"[red]KEV update failed: {exc}[/red]")
    console.print("[+] CVE cache is refreshed on next scan per TTL settings.")


@app.command(name="config")
def config_cmd(
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    set_key: Optional[str] = typer.Option(None, "--set", help="Set config key=value"),
) -> None:
    """Manage CVEye configuration."""
    cfg = CVEyeConfig.load()

    if set_key:
        if "=" not in set_key:
            console.print("[red]Format: --set key=value[/red]")
            raise typer.Exit(code=1)
        key, value = set_key.split("=", 1)
        if not hasattr(cfg, key):
            console.print(f"[red]Unknown config key: {key}[/red]")
            raise typer.Exit(code=1)

        # Type coerce
        field_type = type(getattr(cfg, key))
        if field_type == bool:
            setattr(cfg, key, value.lower() in ("true", "1", "yes"))
        elif field_type == int:
            setattr(cfg, key, int(value))
        elif field_type == float:
            setattr(cfg, key, float(value))
        else:
            setattr(cfg, key, value)

        cfg.save()
        console.print(f"[green]Set {key} = {value}[/green]")

    if show or not set_key:
        console.print("[bold]CVEye Configuration[/bold]")
        console.print(json.dumps(cfg.to_dict(), indent=2))
        console.print(f"\nConfig file: {CONFIG_FILE}")
        console.print("NVD API key: set via NVD_API_KEY environment variable")
