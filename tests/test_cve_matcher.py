"""Tests for CVE version matching."""

from cveye.cve.matcher import match_cve_status
from cveye.cve.models import CVEFinding, CVEStatus, VersionRange
from cveye.network.models import Confidence


def _make_finding(cve_id: str, start_including: str, end_excluding: str) -> CVEFinding:
    return CVEFinding(
        cve_id=cve_id,
        vendor="nginx",
        product="nginx",
        description="Test",
        affected_versions=[
            VersionRange(
                start_including=start_including,
                end_excluding=end_excluding,
            )
        ],
        fixed_version=end_excluding,
    )


def test_match_affected():
    """Version 1.24.0 is within [1.20.0, 1.26.1) -> AFFECTED."""
    finding = _make_finding("CVE-2024-0001", "1.20.0", "1.26.1")
    status = match_cve_status(finding, "1.24.0")
    assert status == CVEStatus.AFFECTED


def test_match_not_affected():
    """Version 1.27.0 is outside [1.20.0, 1.26.1) -> NOT_AFFECTED."""
    finding = _make_finding("CVE-2024-0002", "1.20.0", "1.26.1")
    status = match_cve_status(finding, "1.27.0")
    assert status == CVEStatus.NOT_AFFECTED


def test_match_potentially_affected_low_confidence():
    """No version range -> POTENTIALLY_AFFECTED for known version."""
    finding = CVEFinding(
        cve_id="CVE-2024-0003",
        vendor="nginx",
        product="nginx",
        description="Test",
        affected_versions=[],
    )
    status = match_cve_status(finding, "1.24.0")
    assert status == CVEStatus.POTENTIALLY_AFFECTED


def test_match_unknown_version():
    """None version -> UNKNOWN."""
    finding = _make_finding("CVE-2024-0004", "1.20.0", "1.26.1")
    status = match_cve_status(finding, None)
    assert status == CVEStatus.UNKNOWN
