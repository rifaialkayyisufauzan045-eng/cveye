"""Web scanning engine."""

from __future__ import annotations

from typing import Optional

import httpx

from cveye.logger import get_logger
from cveye.utils.http import RateLimitedClient
from cveye.utils.validators import TargetInfo
from cveye.web.fingerprint import fingerprint_web
from cveye.web.headers import analyze_security_headers
from cveye.web.models import WebScanResult
from cveye.web.tls import scan_tls

logger = get_logger()


def scan_web(
    target: TargetInfo,
    timeout: float = 5.0,
    rate_limit: float = 1.0,
    deep: bool = False,
) -> WebScanResult:
    """Perform web fingerprinting scan."""
    url = target.base_url
    result = WebScanResult(url=url)

    with RateLimitedClient(timeout=timeout, rate_limit=rate_limit) as client:
        # Try primary URL, fall back to HTTPS if needed
        response: Optional[httpx.Response] = None

        for try_url in _url_candidates(target):
            try:
                response = client.get(try_url)
                result.url = try_url
                break
            except Exception as exc:
                logger.debug("Request to %s failed: %s", try_url, exc)

        if response is None:
            return result

        if response.status_code == 429:
            logger.warning("Rate limited (HTTP 429) for %s", url)
            return result

        result.status_code = response.status_code
        result.headers = dict(response.headers)
        # Limit body size
        result.body = response.text[:500_000]

        # TLS info for HTTPS
        if result.url.startswith("https://"):
            result.tls = scan_tls(result.url, timeout=timeout)

        # Security headers
        result.security_headers = analyze_security_headers(result.headers)

        # Fingerprint technologies
        technologies, plugins, themes = fingerprint_web(
            result.url,
            result.status_code or 0,
            result.headers,
            result.body,
        )
        result.technologies = technologies
        result.plugins = plugins
        result.themes = themes

        if deep:
            # Scan extra paths for additional technology signals
            extra_paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]
            for path in extra_paths:
                extra_url = result.url.rstrip("/") + path
                try:
                    extra = client.get(extra_url)
                    if extra.status_code == 200:
                        extra_tech, extra_plugins, _ = fingerprint_web(
                            extra_url,
                            extra.status_code,
                            dict(extra.headers),
                            extra.text[:100_000],
                        )
                        # Merge unique technologies
                        existing = {t.name.lower() for t in result.technologies}
                        for t in extra_tech:
                            if t.name.lower() not in existing:
                                result.technologies.append(t)
                                existing.add(t.name.lower())
                        result.plugins.extend(extra_plugins)
                except Exception:
                    pass

    return result


def _url_candidates(target: TargetInfo) -> list[str]:
    """Generate URL candidates for scanning."""
    host = target.hostname or target.ip or target.input

    if target.is_url:
        return [target.base_url]

    if target.port == 443:
        return [f"https://{host}"]

    return [f"http://{host}", f"https://{host}"]
