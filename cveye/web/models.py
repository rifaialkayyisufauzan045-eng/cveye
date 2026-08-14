"""Web scanning models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cveye.network.models import Confidence


@dataclass
class Technology:
    """Detected web technology."""

    name: str
    category: str
    version: Optional[str] = None
    confidence: Confidence = Confidence.UNKNOWN
    evidence: Optional[str] = None
    source: Optional[str] = None


@dataclass
class SecurityHeader:
    """Security header check result."""

    name: str
    present: bool
    value: Optional[str] = None


@dataclass
class TLSInfo:
    """TLS certificate information."""

    protocol: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_remaining: Optional[int] = None
    status: str = "UNKNOWN"


@dataclass
class WebScanResult:
    """Complete web scan result."""

    url: str
    status_code: Optional[int] = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    technologies: list[Technology] = field(default_factory=list)
    security_headers: list[SecurityHeader] = field(default_factory=list)
    tls: Optional[TLSInfo] = None
    plugins: list[Technology] = field(default_factory=list)
    themes: list[Technology] = field(default_factory=list)
