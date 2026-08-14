"""Security header analysis."""

from __future__ import annotations

from cveye.web.models import SecurityHeader

# List of security headers to check
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]


def analyze_security_headers(headers: dict[str, str]) -> list[SecurityHeader]:
    """Check for presence of security headers."""
    # Normalize incoming header names to lowercase
    normalized = {k.lower(): v for k, v in headers.items()}

    results: list[SecurityHeader] = []
    for header in SECURITY_HEADERS:
        key = header.lower()
        present = key in normalized
        value = normalized.get(key)
        results.append(SecurityHeader(name=header, present=present, value=value))

    return results
