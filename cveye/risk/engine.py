"""Risk assessment engine."""

from __future__ import annotations

from typing import Optional

from cveye.cve.models import CVEFinding, CVEStatus, Severity


def calculate_risk(findings: list[CVEFinding]) -> dict:
    """Calculate overall risk from CVE findings."""
    if not findings:
        return {
            "level": "NONE",
            "score": 0.0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0,
            "kev_count": 0,
        }

    # Count by severity
    severity_counts: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    kev_count = 0
    scores: list[float] = []

    for f in findings:
        if f.status == CVEStatus.NOT_AFFECTED:
            continue
        sev = f.severity.value if f.severity else "UNKNOWN"
        if sev in severity_counts:
            severity_counts[sev] += 1
        if f.cvss_score is not None:
            scores.append(f.cvss_score)
        if f.cisa_kev:
            kev_count += 1

    max_score = max(scores, default=0.0)
    avg_score = sum(scores) / len(scores) if scores else 0.0

    # Determine overall level
    level = "NONE"
    if severity_counts["CRITICAL"] > 0 or max_score >= 9.0:
        level = "CRITICAL"
    elif severity_counts["HIGH"] > 0 or max_score >= 7.0:
        level = "HIGH"
    elif severity_counts["MEDIUM"] > 0 or max_score >= 4.0:
        level = "MEDIUM"
    elif severity_counts["LOW"] > 0 or max_score > 0.0:
        level = "LOW"

    return {
        "level": level,
        "score": round(max_score, 1),
        "avg_score": round(avg_score, 1),
        "critical": severity_counts["CRITICAL"],
        "high": severity_counts["HIGH"],
        "medium": severity_counts["MEDIUM"],
        "low": severity_counts["LOW"],
        "total": sum(severity_counts.values()),
        "kev_count": kev_count,
    }
