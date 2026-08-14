"""CVE Web Search Engine — Chromium-based CVE intelligence layer."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from cveye.config import CVEyeConfig
from cveye.cve.browser import CVEBrowser, PLAYWRIGHT_AVAILABLE
from cveye.cve.client import PRODUCT_MAP, CVEClient
from cveye.cve.kev import KEVCatalog
from cveye.cve.matcher import (
    determine_search_confidence,
    match_cve_status,
    verify_product_match,
)
from cveye.cve.models import (
    CVEIntelligenceResult,
    CVEFinding,
    CVESearchRecord,
    CVEQuery,
    CVEStatus,
    SearchConfidence,
)
from cveye.cve.nvd import NVDClient
from cveye.cve.parser import parse_nvd_cve_page, web_result_from_dict
from cveye.logger import get_logger
from cveye.network.models import Confidence
from cveye.scan import ScanResult
from cveye.web.models import Technology

logger = get_logger()

WEB_CACHE_DIR = Path(".cache") / "cve-web"
WEB_CACHE_TTL = 86400  # 24 hours


def build_search_query(tech: Technology, vendor: str = "") -> str:
    """Build precise CVE search query from detected technology."""
    name = tech.name
    version = tech.version or ""
    if vendor:
        return f'"{name} {version}" vulnerability CVE'
    return f'"{name} {version}" CVE'


def _cache_key(vendor: str, product: str, version: str) -> str:
    return f"{vendor}:{product}:{version}"


def _cache_path(vendor: str, product: str, version: str) -> Path:
    safe_product = product.lower().replace(" ", "_")
    key = _cache_key(vendor, product, version)
    return WEB_CACHE_DIR / safe_product / f"{key}.json"


class CVEWebSearchEngine:
    """Chromium-based CVE web intelligence with NVD API fallback."""

    def __init__(
        self,
        config: CVEyeConfig | None = None,
        headless: bool = True,
        rate_limit_delay: float = 2.0,
    ) -> None:
        self.config = config or CVEyeConfig.load()
        self.headless = headless
        self.rate_limit_delay = rate_limit_delay
        self.nvd = NVDClient(api_key=self.config.nvd_api_key)
        self.kev = KEVCatalog()
        self.fallback_client = CVEClient(self.config)

    def search(self, scan_result: ScanResult) -> CVEIntelligenceResult:
        """
        Run CVE web intelligence on existing scan results.

        Does NOT re-run any scanning — uses scan_result.technologies only.
        """
        intelligence = CVEIntelligenceResult()
        all_findings: list[CVEFinding] = []
        seen_cves: set[str] = set()

        browser: Optional[CVEBrowser] = None
        browser_ok = False

        if PLAYWRIGHT_AVAILABLE:
            browser = CVEBrowser(
                headless=self.headless,
                rate_limit_delay=self.rate_limit_delay,
            )
            browser_ok = browser.start()
            intelligence.browser_used = browser_ok

        if not browser_ok:
            logger.warning("Browser CVE search unavailable")
            intelligence.fallback_used = True

        try:
            for tech in scan_result.technologies:
                record, findings = self._search_technology(tech, browser, browser_ok)
                intelligence.searches.append(record)

                for finding in findings:
                    if finding.cve_id not in seen_cves:
                        seen_cves.add(finding.cve_id)
                        all_findings.append(finding)
                        src = finding.source
                        if src and src not in intelligence.sources:
                            intelligence.sources.append(src)
        finally:
            if browser:
                browser.stop()

        intelligence.findings = sorted(
            all_findings,
            key=lambda f: f.cvss_score or 0,
            reverse=True,
        )
        return intelligence

    def _search_technology(
        self,
        tech: Technology,
        browser: Optional[CVEBrowser],
        browser_ok: bool,
    ) -> tuple[CVESearchRecord, list[CVEFinding]]:
        """Search CVEs for a single technology."""
        key = tech.name.lower()

        # Skip unknown versions
        if not tech.version:
            return CVESearchRecord(
                technology=tech.name,
                version=None,
                vendor="",
                product="",
                query="",
                status="skipped",
                reason="Exact version unavailable",
            ), []

        if key not in PRODUCT_MAP:
            return CVESearchRecord(
                technology=tech.name,
                version=tech.version,
                vendor="",
                product="",
                query="",
                status="skipped",
                reason="Product not in CVE search map",
            ), []

        vendor, product = PRODUCT_MAP[key]
        query = build_search_query(tech, vendor)

        # Check web cache
        cached = self._load_cache(vendor, product, tech.version)
        if cached is not None:
            logger.info("Using cached CVE intelligence for %s %s", tech.name, tech.version)
            return CVESearchRecord(
                technology=tech.name,
                version=tech.version,
                vendor=vendor,
                product=product,
                query=query,
                status="cached",
                results_count=len(cached),
            ), cached

        findings: list[CVEFinding] = []

        # Chromium search + verification
        if browser_ok and browser:
            try:
                findings = self._browser_search(
                    browser, tech, vendor, product, query,
                )
            except Exception as exc:
                logger.warning("Browser CVE search error: %s", exc)

        # Fallback to NVD API
        if not findings:
            intelligence_fallback = True
            if browser_ok and not findings:
                logger.info("Falling back to NVD API/cache for %s", tech.name)
            findings = self._api_fallback(tech, vendor, product)
            if findings and browser_ok:
                pass  # fallback_used set at engine level

        self._save_cache(vendor, product, tech.version, findings)

        return CVESearchRecord(
            technology=tech.name,
            version=tech.version,
            vendor=vendor,
            product=product,
            query=query,
            status="searched" if findings else "no_results",
            results_count=len(findings),
        ), findings

    def _browser_search(
        self,
        browser: CVEBrowser,
        tech: Technology,
        vendor: str,
        product: str,
        query: str,
    ) -> list[CVEFinding]:
        """Search and verify CVEs via Chromium."""
        raw_results = browser.search(query)
        verified: list[CVEFinding] = []

        for raw in raw_results[:10]:
            web_result = web_result_from_dict(raw)
            cve_id = web_result.cve_id
            if not cve_id:
                continue

            # Verify on official source — do NOT trust snippet alone
            html = browser.verify_cve(cve_id)
            if not html:
                continue

            finding = parse_nvd_cve_page(html, cve_id)
            if not finding:
                continue

            finding.vendor = finding.vendor or vendor
            finding.product = finding.product or product
            finding.detected_version = tech.version
            finding.reference_url = web_result.url

            vendor_match, product_match = verify_product_match(finding, vendor, product)
            if not product_match:
                continue

            finding.status = match_cve_status(finding, tech.version, tech.confidence)
            if finding.status == CVEStatus.NOT_AFFECTED:
                continue

            version_matched = finding.status in (
                CVEStatus.AFFECTED,
                CVEStatus.POTENTIALLY_AFFECTED,
            )
            finding.search_confidence = determine_search_confidence(
                finding,
                vendor_match=vendor_match,
                product_match=product_match,
                version_matched=version_matched,
                official_source=True,
            )

            # Skip LOW confidence search-only results
            if finding.search_confidence == SearchConfidence.LOW and not finding.affected_versions:
                continue

            finding.cisa_kev = self.kev.is_known_exploited(cve_id)
            verified.append(finding)

        return verified

    def _api_fallback(
        self,
        tech: Technology,
        vendor: str,
        product: str,
    ) -> list[CVEFinding]:
        """Fall back to NVD API when browser search unavailable."""
        query = CVEQuery(vendor=vendor, product=product, version=tech.version)
        findings = self.nvd.search(query, cache_ttl=self.config.cache_ttl_hours)

        verified: list[CVEFinding] = []
        for finding in findings:
            finding.detected_version = tech.version
            finding.status = match_cve_status(finding, tech.version, tech.confidence)
            if finding.status == CVEStatus.NOT_AFFECTED:
                continue

            vendor_match, product_match = verify_product_match(finding, vendor, product)
            finding.search_confidence = determine_search_confidence(
                finding,
                vendor_match=vendor_match,
                product_match=product_match,
                version_matched=finding.status != CVEStatus.UNKNOWN,
                official_source=True,
            )
            finding.cisa_kev = self.kev.is_known_exploited(finding.cve_id)
            verified.append(finding)

        return verified

    def _load_cache(
        self,
        vendor: str,
        product: str,
        version: str,
    ) -> Optional[list[CVEFinding]]:
        path = _cache_path(vendor, product, version)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if time.time() - data.get("timestamp", 0) > WEB_CACHE_TTL:
                return None
            return [_finding_from_cache(f) for f in data.get("findings", [])]
        except (json.JSONDecodeError, OSError, KeyError):
            return None

    def _save_cache(
        self,
        vendor: str,
        product: str,
        version: str,
        findings: list[CVEFinding],
    ) -> None:
        path = _cache_path(vendor, product, version)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "timestamp": time.time(),
                    "key": _cache_key(vendor, product, version),
                    "findings": [_finding_to_cache(f) for f in findings],
                },
                indent=2,
            ),
            encoding="utf-8",
        )


def _finding_to_cache(f: CVEFinding) -> dict:
    return {
        "cve_id": f.cve_id,
        "vendor": f.vendor,
        "product": f.product,
        "description": f.description,
        "cvss_score": f.cvss_score,
        "severity": f.severity.value,
        "cwe": f.cwe,
        "status": f.status.value,
        "detected_version": f.detected_version,
        "source": f.source,
        "search_confidence": f.search_confidence.value if f.search_confidence else None,
        "reference_url": f.reference_url,
        "cisa_kev": f.cisa_kev,
        "affected_versions": [
            {
                "start_including": vr.start_including,
                "start_excluding": vr.start_excluding,
                "end_including": vr.end_including,
                "end_excluding": vr.end_excluding,
            }
            for vr in f.affected_versions
        ],
        "fixed_version": f.fixed_version,
        "references": f.references,
    }


def _finding_from_cache(d: dict) -> CVEFinding:
    from cveye.cve.models import Severity, VersionRange

    sc = d.get("search_confidence")
    return CVEFinding(
        cve_id=d["cve_id"],
        vendor=d.get("vendor", ""),
        product=d.get("product", ""),
        description=d.get("description", ""),
        cvss_score=d.get("cvss_score"),
        severity=Severity(d.get("severity", "NONE")),
        cwe=d.get("cwe", []),
        status=CVEStatus(d.get("status", "UNKNOWN")),
        detected_version=d.get("detected_version"),
        source=d.get("source", "NVD"),
        search_confidence=SearchConfidence(sc) if sc else None,
        reference_url=d.get("reference_url"),
        cisa_kev=d.get("cisa_kev", False),
        affected_versions=[VersionRange(**vr) for vr in d.get("affected_versions", [])],
        fixed_version=d.get("fixed_version"),
        references=d.get("references", []),
    )
