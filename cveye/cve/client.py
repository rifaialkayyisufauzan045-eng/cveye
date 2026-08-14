"""CVE client and product mapping dictionary."""

from __future__ import annotations

from typing import Optional

from cveye.config import CVEyeConfig
from cveye.cve.models import CVEFinding, CVEIntelligenceResult, CVEQuery
from cveye.cve.nvd import NVDClient

# Dictionary mapping detected technology names -> (vendor, product)
PRODUCT_MAP: dict[str, tuple[str, str]] = {
    "php": ("php", "php"),
    "nginx": ("nginx", "nginx"),
    "wordpress": ("wordpress", "wordpress"),
    "mysql": ("oracle", "mysql"),
    "apache": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "litespeed": ("litespeedtech", "litespeed_web_server"),
    "litespeed web server": ("litespeedtech", "litespeed_web_server"),
    "python": ("python", "python"),
    "node.js": ("nodejs", "node.js"),
    "express": ("expressjs", "express"),
    "react": ("facebook", "react"),
    "vue.js": ("vuejs", "vue"),
    "laravel": ("laravel", "laravel"),
    "django": ("djangoproject", "django"),
    "joomla": ("joomla", "joomla!"),
    "drupal": ("drupal", "drupal"),
    "openssl": ("openssl", "openssl"),
    "openssh": ("openbsd", "openssh"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "postgresql": ("postgresql", "postgresql"),
    "iis": ("microsoft", "internet_information_services"),
}


class CVEClient:
    """General client interface for CVE lookup fallback."""

    def __init__(self, config: Optional[CVEyeConfig] = None) -> None:
        self.config = config or CVEyeConfig.load()
        self.nvd_client = NVDClient(api_key=self.config.nvd_api_key)

    def search(self, query: CVEQuery) -> list[CVEFinding]:
        """Search CVEs via NVD API client."""
        return self.nvd_client.search(query, cache_ttl=self.config.cache_ttl_hours)

    def correlate_technologies(
        self,
        technologies: list,
    ) -> CVEIntelligenceResult:
        """
        Correlate detected technologies with CVE intelligence.

        This is the primary integration point called from cli.py after
        version detection. It uses CVEWebSearchEngine (Chromium + NVD API)
        as the intelligence backend.

        Args:
            technologies: list of Technology objects from scan_result.technologies

        Returns:
            CVEIntelligenceResult with all findings, searches, and sources.
        """
        from cveye.cve.search import CVEWebSearchEngine
        from cveye.scan import ScanResult

        # Build a minimal ScanResult containing only the technologies
        # so the web search engine can operate without re-scanning
        mini_scan = ScanResult(
            target="",
            technologies=list(technologies),
        )

        engine = CVEWebSearchEngine(
            config=self.config,
            headless=True,
        )
        return engine.search(mini_scan)
