"""CVE Intelligence Console and Terminal Formatter."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from cveye.cve.models import CVEIntelligenceResult, CVEStatus, SearchConfidence, Severity

console = Console()


def print_cve_search_terminal_output(intelligence: CVEIntelligenceResult) -> None:
    """Format and print CVE Web Intelligence terminal output."""
    console.print("\nCVE WEB INTELLIGENCE")
    console.print("─" * 36)

    for search in intelligence.searches:
        name_ver = f"{search.technology} {search.version}" if search.version else search.technology
        if search.status == "skipped" or not search.version:
            console.print(f"[yellow][!][/yellow] {name_ver}")
            console.print(f"    CVE search skipped ({search.reason or 'Exact version unavailable'})")
        else:
            console.print(f"[green][+][/green] {name_ver}")
            if search.status == "cached":
                console.print("    Using cached CVE intelligence")
            else:
                console.print("    Searching CVE...")

    console.print("\nCVE FINDINGS")

    # Group findings by technology / version
    grouped: dict[str, list] = {}
    for finding in intelligence.findings:
        key = f"{finding.product.title()} {finding.detected_version or ''}".strip()
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(finding)

    if not grouped:
        console.print("[dim]No CVE vulnerabilities identified.[/dim]")
        return

    for tech_header, findings in grouped.items():
        console.print(f"\n{tech_header}")
        console.print("─" * 20)

        for f in findings:
            sev_color = (
                "red"
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
                else "yellow"
                if f.severity == Severity.MEDIUM
                else "blue"
            )
            console.print(f"[{sev_color}][{f.severity.value}][/{sev_color}]")
            console.print(f"CVE ID     : {f.cve_id}")
            console.print(f"Status     : {f.status.value}")
            console.print(f"CVSS       : {f.cvss_score if f.cvss_score is not None else 'N/A'}")
            console.print(f"Source     : {f.source}")
            conf_str = f.search_confidence.value if f.search_confidence else "N/A"
            console.print(f"Confidence : {conf_str}")
            if f.reference_url:
                console.print(f"Reference  : {f.reference_url}")
            elif f.references:
                console.print(f"Reference  : {f.references[0]}")
            console.print()
