"""CVE data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class CVEStatus(str, Enum):
    """CVE status matching result."""

    AFFECTED = "AFFECTED"
    POTENTIALLY_AFFECTED = "POTENTIALLY_AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    """CVSS Severity ratings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class SearchConfidence(str, Enum):
    """Confidence level for CVE search findings."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class VersionRange:
    """Affected version range representation."""

    start_including: Optional[str] = None
    start_excluding: Optional[str] = None
    end_including: Optional[str] = None
    end_excluding: Optional[str] = None

    def to_string(self) -> str:
        parts = []
        if self.start_including:
            parts.append(f">= {self.start_including}")
        if self.start_excluding:
            parts.append(f"> {self.start_excluding}")
        if self.end_including:
            parts.append(f"<= {self.end_including}")
        if self.end_excluding:
            parts.append(f"< {self.end_excluding}")
        return " ".join(parts) if parts else "unknown"


@dataclass
class CVEQuery:
    """Query for CVE lookup."""

    vendor: str
    product: str
    version: Optional[str] = None


@dataclass
class CVEFinding:
    """A correlated CVE finding."""

    cve_id: str
    vendor: str
    product: str
    description: str
    cvss_score: Optional[float] = None
    severity: Severity = Severity.NONE
    cwe: list[str] = field(default_factory=list)
    published_date: Optional[str] = None
    modified_date: Optional[str] = None
    affected_versions: list[VersionRange] = field(default_factory=list)
    fixed_version: Optional[str] = None
    references: list[str] = field(default_factory=list)
    cisa_kev: bool = False
    status: CVEStatus = CVEStatus.UNKNOWN
    detected_version: Optional[str] = None
    source: str = "NVD"
    search_confidence: Optional[SearchConfidence] = None
    reference_url: Optional[str] = None


@dataclass
class CVEWebResult:
    """Result from web discovery search engine."""

    cve_id: str
    title: str
    url: str
    source: str
    snippet: str


@dataclass
class CVESearchRecord:
    """Record of a CVE search operation for a technology."""

    technology: str
    version: Optional[str]
    vendor: str
    product: str
    query: str
    status: str
    reason: Optional[str] = None
    results_count: int = 0


@dataclass
class CVEIntelligenceResult:
    """Aggregated CVE Web Intelligence results."""

    sources: list[str] = field(default_factory=list)
    findings: list[CVEFinding] = field(default_factory=list)
    searches: list[CVESearchRecord] = field(default_factory=list)
    browser_used: bool = False
    fallback_used: bool = False
