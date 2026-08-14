"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cveye.scan import ScanResult


def _port_to_dict(port) -> dict:
    return {
        "port": port.port,
        "protocol": port.protocol,
        "state": port.state,
        "service": port.service,
        "version": port.version,
        "confidence": port.confidence.value if port.confidence else None,
        "banner": port.banner,
    }


def _tech_to_dict(tech) -> dict:
    return {
        "name": tech.name,
        "category": tech.category,
        "version": tech.version,
        "confidence": tech.confidence.value if tech.confidence else None,
        "evidence": tech.evidence,
        "source": tech.source,
    }


def _finding_to_dict(f) -> dict:
    return {
        "cve_id": f.cve_id,
        "vendor": f.vendor,
        "product": f.product,
        "description": f.description,
        "cvss_score": f.cvss_score,
        "severity": f.severity.value if f.severity else None,
        "status": f.status.value if f.status else None,
        "detected_version": f.detected_version,
        "source": f.source,
        "confidence": f.search_confidence.value if f.search_confidence else None,
        "cisa_kev": f.cisa_kev,
        "references": f.references,
        "reference_url": f.reference_url,
    }


def _cve_intelligence_to_dict(intel) -> dict:
    if intel is None:
        return {}
    return {
        "browser_used": intel.browser_used,
        "fallback_used": intel.fallback_used,
        "sources": intel.sources,
        "findings": [_finding_to_dict(f) for f in intel.findings],
        "searches": [
            {
                "technology": s.technology,
                "version": s.version,
                "vendor": s.vendor,
                "product": s.product,
                "query": s.query,
                "status": s.status,
                "reason": s.reason,
                "results_count": s.results_count,
            }
            for s in intel.searches
        ],
    }


def scan_result_to_dict(result: ScanResult) -> dict:
    """Convert ScanResult to JSON-serializable dict."""
    data: dict[str, Any] = {
        "target": result.target,
        "ip": result.ip,
        "ports": [_port_to_dict(p) for p in result.ports],
        "technologies": [_tech_to_dict(t) for t in result.technologies],
    }

    if result.web_result:
        wr = result.web_result
        data["web"] = {
            "url": wr.url,
            "status_code": wr.status_code,
            "technologies": [_tech_to_dict(t) for t in wr.technologies],
            "plugins": [_tech_to_dict(p) for p in wr.plugins],
            "themes": [_tech_to_dict(t) for t in wr.themes],
            "security_headers": [
                {"name": h.name, "present": h.present, "value": h.value}
                for h in wr.security_headers
            ],
            "tls": {
                "protocol": wr.tls.protocol,
                "subject": wr.tls.subject,
                "issuer": wr.tls.issuer,
                "valid_from": wr.tls.valid_from,
                "valid_until": wr.tls.valid_until,
                "days_remaining": wr.tls.days_remaining,
                "status": wr.tls.status,
            } if wr.tls else None,
        }

    if result.cve_intelligence:
        data["cve_intelligence"] = _cve_intelligence_to_dict(result.cve_intelligence)

    return data


def write_json_report(result: ScanResult, path: str | Path) -> None:
    """Write scan result to JSON file."""
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = scan_result_to_dict(result)
    output_path.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8",
    )
