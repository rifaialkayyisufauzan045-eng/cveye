"""Tests for security header analysis."""

from cveye.web.headers import analyze_security_headers


def test_security_headers_present():
    """Check that present headers are detected."""
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }
    results = analyze_security_headers(headers)
    present = {r.name: r.present for r in results}

    assert present["strict-transport-security"] is True
    assert present["x-content-type-options"] is True
    assert present["x-frame-options"] is True


def test_security_headers_missing():
    """Empty headers -> all missing."""
    results = analyze_security_headers({})
    assert all(not r.present for r in results)
