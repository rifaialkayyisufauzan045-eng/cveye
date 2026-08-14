"""Tests for CVSS scoring and risk calculation."""

from cveye.cve.cvss import score_to_severity
from cveye.cve.models import CVEFinding, CVEStatus, Severity
from cveye.risk.engine import calculate_risk


def test_score_to_severity():
    """CVSS score -> Severity mapping."""
    assert score_to_severity(9.8) == Severity.CRITICAL
    assert score_to_severity(7.5) == Severity.HIGH
    assert score_to_severity(5.0) == Severity.MEDIUM
    assert score_to_severity(2.0) == Severity.LOW
    assert score_to_severity(0.0) == Severity.NONE
    assert score_to_severity(None) == Severity.UNKNOWN


def test_risk_calculation():
    """Risk calculation from findings."""
    findings = [
        CVEFinding(
            cve_id="CVE-2024-0001",
            vendor="nginx",
            product="nginx",
            description="Test",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            status=CVEStatus.AFFECTED,
        ),
        CVEFinding(
            cve_id="CVE-2024-0002",
            vendor="php",
            product="php",
            description="Test",
            severity=Severity.MEDIUM,
            cvss_score=5.5,
            status=CVEStatus.AFFECTED,
        ),
    ]
    summary = calculate_risk(findings)
    assert summary["level"] == "CRITICAL"
    assert summary["critical"] == 1
    assert summary["medium"] == 1
    assert summary["total"] == 2


def test_risk_no_findings():
    """No findings -> NONE risk."""
    summary = calculate_risk([])
    assert summary["level"] == "NONE"
    assert summary["total"] == 0
