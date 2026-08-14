"""Network scanning models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class PortResult:
    """Port scan result."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: Confidence = Confidence.UNKNOWN
    evidence: Optional[str] = None


@dataclass
class ServiceFingerprint:
    """Service fingerprint result."""

    port: int
    protocol: str
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    confidence: Confidence = Confidence.UNKNOWN
    evidence: Optional[str] = None


@dataclass
class NetworkScanResult:
    """Complete network scan result."""

    host: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    ports: list[PortResult] = field(default_factory=list)
    services: list[ServiceFingerprint] = field(default_factory=list)
