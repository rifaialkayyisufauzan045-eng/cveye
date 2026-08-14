"""CVSS score and severity utilities."""

from __future__ import annotations

from typing import Optional

from cveye.cve.models import Severity


def score_to_severity(score: Optional[float]) -> Severity:
    """Convert a CVSS score to Severity enum rating."""
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.NONE
