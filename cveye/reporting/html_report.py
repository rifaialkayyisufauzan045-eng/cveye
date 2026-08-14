"""HTML report writer."""

from __future__ import annotations

from pathlib import Path

from cveye.scan import ScanResult


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVEye Report — {target}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
        h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
        h2 {{ color: #79c0ff; margin-top: 30px; }}
        h3 {{ color: #d2a8ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th {{ background: #161b22; color: #58a6ff; padding: 8px 12px; text-align: left; border: 1px solid #30363d; }}
        td {{ padding: 8px 12px; border: 1px solid #21262d; }}
        tr:nth-child(even) {{ background: #161b22; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.85em; font-weight: bold; }}
        .badge-critical {{ background: #da3633; }}
        .badge-high {{ background: #d29922; color: #0d1117; }}
        .badge-medium {{ background: #388bfd; }}
        .badge-low {{ background: #3fb950; color: #0d1117; }}
        .badge-none {{ background: #6e7681; }}
        .badge-ok {{ background: #3fb950; color: #0d1117; }}
        .badge-miss {{ background: #da3633; }}
        .cve-block {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; margin: 10px 0; }}
        .cve-id {{ font-size: 1.1em; font-weight: bold; color: #58a6ff; }}
        .meta {{ color: #8b949e; font-size: 0.9em; }}
        a {{ color: #58a6ff; }}
    </style>
</head>
<body>
    <h1>CVEye Scan Report</h1>
    <p><strong>Target:</strong> {target}</p>
    {ip_line}
    <hr style="border-color:#30363d">

    {open_ports_section}
    {technologies_section}
    {security_headers_section}
    {tls_section}
    {cve_section}
</body>
</html>
"""


def _severity_badge(sev: str) -> str:
    cls = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "LOW": "badge-low",
    }.get(sev.upper(), "badge-none")
    return f'<span class="badge {cls}">{sev}</span>'


def _build_ports_section(result: ScanResult) -> str:
    if not result.ports:
        return ""
    rows = ""
    for p in result.ports:
        rows += (
            f"<tr><td>{p.port}</td><td>{p.protocol}</td>"
            f"<td>{p.service or ''}</td><td>{p.version or ''}</td>"
            f"<td>{p.confidence.value if p.confidence else ''}</td></tr>\n"
        )
    return f"""
    <h2>Open Ports</h2>
    <table>
        <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Confidence</th></tr>
        {rows}
    </table>
    """


def _build_technologies_section(result: ScanResult) -> str:
    techs = result.technologies or []
    if result.web_result:
        techs = list(result.web_result.technologies) + [
            t for t in techs if t not in result.web_result.technologies
        ]
    if not techs:
        return ""
    rows = ""
    for t in techs:
        rows += (
            f"<tr><td>{t.name}</td><td>{t.category}</td>"
            f"<td>{t.version or ''}</td>"
            f"<td>{t.confidence.value if t.confidence else ''}</td></tr>\n"
        )
    return f"""
    <h2>Web Technologies</h2>
    <table>
        <tr><th>Name</th><th>Category</th><th>Version</th><th>Confidence</th></tr>
        {rows}
    </table>
    """


def _build_security_headers_section(result: ScanResult) -> str:
    if not result.web_result or not result.web_result.security_headers:
        return ""
    rows = ""
    for h in result.web_result.security_headers:
        badge = '<span class="badge badge-ok">✓ Present</span>' if h.present else '<span class="badge badge-miss">✗ Missing</span>'
        rows += f"<tr><td>{h.name}</td><td>{badge}</td><td>{h.value or ''}</td></tr>\n"
    return f"""
    <h2>Security Headers</h2>
    <table>
        <tr><th>Header</th><th>Status</th><th>Value</th></tr>
        {rows}
    </table>
    """


def _build_tls_section(result: ScanResult) -> str:
    if not result.web_result or not result.web_result.tls:
        return ""
    tls = result.web_result.tls
    rows = ""
    for label, value in [
        ("Protocol", tls.protocol),
        ("Subject", tls.subject),
        ("Issuer", tls.issuer),
        ("Valid From", tls.valid_from),
        ("Valid Until", tls.valid_until),
        ("Days Remaining", tls.days_remaining),
        ("Status", tls.status),
    ]:
        if value is not None:
            rows += f"<tr><td>{label}</td><td>{value}</td></tr>\n"
    return f"""
    <h2>TLS Certificate</h2>
    <table>
        <tr><th>Field</th><th>Value</th></tr>
        {rows}
    </table>
    """


def _build_cve_section(result: ScanResult) -> str:
    if not result.cve_intelligence or not result.cve_intelligence.findings:
        return "<h2>CVE Intelligence</h2><p>No CVE vulnerabilities identified.</p>"

    intel = result.cve_intelligence
    blocks = ""
    for f in intel.findings:
        sev = f.severity.value if f.severity else "UNKNOWN"
        badge = _severity_badge(sev)
        status = f.status.value if f.status else "UNKNOWN"
        score_str = str(f.cvss_score) if f.cvss_score is not None else "N/A"
        conf = f.search_confidence.value if f.search_confidence else "N/A"
        kev = " <span class='badge badge-critical'>KEV</span>" if f.cisa_kev else ""
        ref = ""
        ref_url = f.reference_url or (f.references[0] if f.references else None)
        if ref_url:
            ref = f'<p class="meta">Reference: <a href="{ref_url}">{ref_url}</a></p>'

        blocks += f"""
        <div class="cve-block">
            <div class="cve-id">{f.cve_id} {badge}{kev}</div>
            <p>{f.description[:300]}...</p>
            <p class="meta">
                Product: {f.product} {f.detected_version or ''} &nbsp;|&nbsp;
                Status: {status} &nbsp;|&nbsp;
                CVSS: {score_str} &nbsp;|&nbsp;
                Source: {f.source} &nbsp;|&nbsp;
                Confidence: {conf}
            </p>
            {ref}
        </div>
        """

    return f"<h2>CVE Intelligence</h2>{blocks}"


def write_html_report(result: ScanResult, path: str | Path) -> None:
    """Write scan result to HTML file."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    ip_line = f"<p><strong>IP:</strong> {result.ip}</p>" if result.ip else ""

    html = _HTML_TEMPLATE.format(
        target=result.target,
        ip_line=ip_line,
        open_ports_section=_build_ports_section(result),
        technologies_section=_build_technologies_section(result),
        security_headers_section=_build_security_headers_section(result),
        tls_section=_build_tls_section(result),
        cve_section=_build_cve_section(result),
    )

    output_path.write_text(html, encoding="utf-8")
