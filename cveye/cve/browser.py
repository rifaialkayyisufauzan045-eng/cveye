"""Chromium browser engine for CVE web search."""

from __future__ import annotations

import time
from typing import Optional
from urllib.parse import quote_plus

from cveye.logger import get_logger

logger = get_logger()

PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import Browser, BrowserContext, Page, Playwright, sync_playwright

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    Browser = BrowserContext = Page = Playwright = None  # type: ignore[misc, assignment]


# Trusted CVE source domains (discovery only — verification required)
TRUSTED_DOMAINS = (
    "nvd.nist.gov",
    "cve.org",
    "cve.mitre.org",
    "cisa.gov",
    "wordpress.org",
    "php.net",
    "nginx.org",
)


class CVEBrowser:
    """Headless Chromium browser for CVE information discovery."""

    def __init__(
        self,
        headless: bool = True,
        timeout_ms: int = 30000,
        rate_limit_delay: float = 2.0,
    ) -> None:
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.rate_limit_delay = rate_limit_delay
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._last_request = 0.0

    @property
    def available(self) -> bool:
        return PLAYWRIGHT_AVAILABLE

    def start(self) -> bool:
        """Launch Chromium browser."""
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright not installed")
            return False
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=self.headless)
            self._context = self._browser.new_context(
                user_agent="CVEye/1.0 CVE Intelligence Tool",
                ignore_https_errors=False,
            )
            self._context.set_default_timeout(self.timeout_ms)
            return True
        except Exception as exc:
            logger.warning("Failed to launch Chromium: %s", exc)
            self.stop()
            return False

    def stop(self) -> None:
        """Close browser and cleanup."""
        try:
            if self._context:
                self._context.close()
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass
        finally:
            self._context = None
            self._browser = None
            self._playwright = None

    def __enter__(self) -> CVEBrowser:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop()

    def _wait_rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request
        wait = self.rate_limit_delay - elapsed
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def _new_page(self) -> Page:
        if not self._context:
            raise RuntimeError("Browser not started")
        return self._context.new_page()

    def search(self, query: str) -> list[dict[str, str]]:
        """
        Search for CVE information using NVD site search and discovery.

        Returns list of dicts with keys: cve_id, title, url, source, snippet.
        """
        if not self._context:
            return []

        results: list[dict[str, str]] = []
        seen: set[str] = set()

        # Primary: NVD site search
        nvd_results = self._search_nvd(query)
        for item in nvd_results:
            cve_id = item.get("cve_id", "")
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                results.append(item)

        self._wait_rate_limit()

        # Discovery: DuckDuckGo for trusted sources
        if len(results) < 5:
            ddg_results = self._search_discovery(query)
            for item in ddg_results:
                cve_id = item.get("cve_id", "")
                if cve_id and cve_id not in seen:
                    seen.add(cve_id)
                    results.append(item)

        return results[:20]

    def _search_nvd(self, query: str) -> list[dict[str, str]]:
        """Search NVD website directly."""
        results: list[dict[str, str]] = []
        try:
            self._wait_rate_limit()
            page = self._new_page()
            encoded = quote_plus(query)
            url = f"https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={encoded}"
            response = page.goto(url, wait_until="domcontentloaded")
            if response and response.status == 429:
                logger.warning("NVD rate limited (HTTP 429)")
                page.close()
                return results

            page.wait_for_timeout(1500)
            content = page.content()
            page.close()

            from cveye.cve.parser import parse_nvd_search_results

            results = parse_nvd_search_results(content)
        except Exception as exc:
            logger.debug("NVD browser search failed: %s", exc)
        return results

    def _search_discovery(self, query: str) -> list[dict[str, str]]:
        """Use search engine to discover CVE pages on trusted domains."""
        results: list[dict[str, str]] = []
        try:
            self._wait_rate_limit()
            page = self._new_page()
            ddg_query = quote_plus(f'{query} CVE site:nvd.nist.gov OR site:cve.org')
            url = f"https://html.duckduckgo.com/html/?q={ddg_query}"
            response = page.goto(url, wait_until="domcontentloaded")
            if response and response.status == 429:
                logger.warning("Search rate limited (HTTP 429)")
                page.close()
                return results

            page.wait_for_timeout(1000)
            content = page.content()
            page.close()

            from cveye.cve.parser import parse_discovery_results

            results = parse_discovery_results(content)
        except Exception as exc:
            logger.debug("Discovery search failed: %s", exc)
        return results

    def fetch_page(self, url: str) -> Optional[str]:
        """Fetch a trusted source page for CVE verification."""
        if not self._context:
            return None
        if not any(domain in url for domain in TRUSTED_DOMAINS):
            logger.debug("Skipping untrusted URL: %s", url)
            return None

        try:
            self._wait_rate_limit()
            page = self._new_page()
            response = page.goto(url, wait_until="domcontentloaded")
            if response and response.status == 429:
                logger.warning("Source page rate limited (HTTP 429)")
                page.close()
                return None
            page.wait_for_timeout(1000)
            content = page.content()
            page.close()
            return content
        except Exception as exc:
            logger.debug("Failed to fetch %s: %s", url, exc)
            return None

    def verify_cve(self, cve_id: str) -> Optional[str]:
        """Open official NVD page and return HTML for verification."""
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        return self.fetch_page(url)
