"""TLS certificate scanning."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from cveye.web.models import TLSInfo


def scan_tls(url: str, timeout: float = 5.0) -> Optional[TLSInfo]:
    """Analyze TLS certificate for HTTPS URL."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None

    host = parsed.hostname
    if not host:
        return None
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

        subject = _format_name(cert.get("subject", ()))
        issuer = _format_name(cert.get("issuer", ()))
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        valid_from = _parse_cert_date(not_before)
        valid_until = _parse_cert_date(not_after)

        days_remaining: Optional[int] = None
        status = "UNKNOWN"

        now = datetime.now(tz=timezone.utc)
        if valid_until:
            delta = valid_until - now
            days_remaining = delta.days
            if days_remaining < 0:
                status = "EXPIRED"
            elif days_remaining < 30:
                status = "EXPIRING_SOON"
            else:
                status = "VALID"

        return TLSInfo(
            protocol=protocol,
            subject=subject,
            issuer=issuer,
            valid_from=not_before,
            valid_until=not_after,
            days_remaining=days_remaining,
            status=status,
        )

    except Exception:
        return None


def _format_name(name_tuple: tuple) -> str:
    """Format cert name tuple to string."""
    parts = []
    for rdn in name_tuple:
        for attr_type, value in rdn:
            parts.append(f"{attr_type}={value}")
    return ", ".join(parts)


def _parse_cert_date(date_str: str) -> Optional[datetime]:
    """Parse certificate date string."""
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
