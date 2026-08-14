"""Scanning orchestration and result aggregate model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cveye.cve.models import CVEIntelligenceResult
from cveye.network.models import NetworkScanResult, PortResult
from cveye.web.models import Technology, WebScanResult


@dataclass
class ScanResult:
    """Aggregated scanning result for a target."""

    target: str
    ip: Optional[str] = None
    ports: list[PortResult] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    web_result: Optional[WebScanResult] = None
    # network_result: single host (legacy compat)
    network_result: Optional[NetworkScanResult] = None
    # network: list of all scanned hosts (multi-host / CIDR support)
    network: list[NetworkScanResult] = field(default_factory=list)
    cve_intelligence: Optional[CVEIntelligenceResult] = None
