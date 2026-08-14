"""NVD API client fallback implementation."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import requests

from cveye.cve.cvss import score_to_severity
from cveye.cve.models import CVEFinding, CVEQuery, VersionRange
from cveye.logger import get_logger

logger = get_logger()

NVD_CACHE_DIR = Path(".cache") / "cve"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClient:
    """Client for NVD REST API 2.0 with caching."""

    def __init__(self, api_key: str = "") -> None:
        self.api_key = api_key

    def search(self, query: CVEQuery, cache_ttl: int = 24) -> list[CVEFinding]:
        """Search NVD API for product and version."""
        cached = self._load_cache(query, cache_ttl)
        if cached is not None:
            return cached

        findings: list[CVEFinding] = []
        try:
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            params = {"keywordSearch": f"{query.product} {query.version or ''}".strip()}
            resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("vulnerabilities", []):
                    cve_data = item.get("cve", {})
                    finding = _parse_nvd_api_cve(cve_data)
                    if finding:
                        finding.vendor = query.vendor
                        finding.product = query.product
                        findings.append(finding)

            self._save_cache(query, findings)
        except Exception as exc:
            logger.debug("NVD API request failed: %s", exc)

        return findings

    def _cache_path(self, query: CVEQuery) -> Path:
        safe_product = query.product.lower().replace(" ", "_")
        v = query.version or "unknown"
        return NVD_CACHE_DIR / safe_product / f"{query.vendor}_{safe_product}_{v}.json"

    def _load_cache(self, query: CVEQuery, cache_ttl_hours: int) -> Optional[list[CVEFinding]]:
        path = self._cache_path(query)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if time.time() - data.get("timestamp", 0) > cache_ttl_hours * 3600:
                return None
            from cveye.cve.search import _finding_from_cache

            return [_finding_from_cache(f) for f in data.get("findings", [])]
        except Exception:
            return None

    def _save_cache(self, query: CVEQuery, findings: list[CVEFinding]) -> None:
        path = self._cache_path(query)
        path.parent.mkdir(parents=True, exist_ok=True)
        from cveye.cve.search import _finding_to_cache

        try:
            path.write_text(
                json.dumps(
                    {
                        "timestamp": time.time(),
                        "findings": [_finding_to_cache(f) for f in findings],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except Exception:
            pass


def _parse_nvd_api_cve(cve: dict) -> Optional[CVEFinding]:
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # Description
    descriptions = cve.get("descriptions", [])
    desc_text = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc_text = d.get("value", "")
            break

    # CVSS score
    metrics = cve.get("metrics", {})
    score: Optional[float] = None
    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
        score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")
    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")

    # CWE
    cwes: list[str] = []
    for problem in cve.get("weaknesses", []):
        for d in problem.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)

    # References
    refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

    return CVEFinding(
        cve_id=cve_id,
        vendor="",
        product="",
        description=desc_text,
        cvss_score=score,
        severity=score_to_severity(score),
        cwe=cwes[:5],
        references=refs[:10],
        source="NVD API",
    )
