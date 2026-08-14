"""Web technology fingerprinting."""

from __future__ import annotations

import re
from typing import Optional

from bs4 import BeautifulSoup

from cveye.network.models import Confidence
from cveye.web.models import Technology
from cveye.web.wordpress import detect_wordpress


def fingerprint_web(
    url: str,
    status_code: int,
    headers: dict[str, str],
    body: str,
) -> tuple[list[Technology], list[Technology], list[Technology]]:
    """Run all web fingerprint detectors.

    Returns (technologies, plugins, themes).
    """
    technologies: list[Technology] = []
    plugins: list[Technology] = []
    themes: list[Technology] = []

    # Normalize headers
    normalized_headers = {k.lower(): v for k, v in headers.items()}

    # Server header
    server = normalized_headers.get("server", "")
    if server:
        tech = _parse_server_header(server)
        if tech:
            technologies.append(tech)

    # X-Powered-By header
    powered = normalized_headers.get("x-powered-by", "")
    if powered:
        tech = _parse_powered_by(powered)
        if tech:
            technologies.append(tech)

    # WordPress detection
    wp_tech, wp_plugins, wp_themes = detect_wordpress(body, headers, url)
    if wp_tech:
        technologies.append(wp_tech)
    plugins.extend(wp_plugins)
    themes.extend(wp_themes)

    # HTML-based detections
    soup = BeautifulSoup(body, "html.parser")

    php_tech = _detect_php_html(body)
    if php_tech:
        # Only add PHP from HTML if not already detected
        existing_names = {t.name.lower() for t in technologies}
        if "php" not in existing_names:
            technologies.append(php_tech)

    drupal = _detect_drupal(body, headers)
    if drupal:
        technologies.append(drupal)

    joomla = _detect_joomla(body)
    if joomla:
        technologies.append(joomla)

    laravel = _detect_laravel(headers, body)
    if laravel:
        technologies.append(laravel)

    django = _detect_django(headers)
    if django:
        technologies.append(django)

    node = _detect_node(headers, body)
    if node:
        technologies.append(node)

    nextjs = _detect_nextjs(body)
    if nextjs:
        technologies.append(nextjs)

    return technologies, plugins, themes


def _parse_server_header(server: str) -> Optional[Technology]:
    """Parse Server header into Technology."""
    # Pattern: Name/Version
    ver_match = re.search(r"([\w.-]+)/([\d.]+)", server)
    if ver_match:
        name = _normalize_server_name(ver_match.group(1))
        version = ver_match.group(2)
        return Technology(
            name=name,
            category="Web Server",
            version=version,
            confidence=Confidence.HIGH,
            evidence=f"Server: {server}",
            source="Server header",
        )

    # No version — just name
    name = _normalize_server_name(server.split("/")[0].strip())
    if name:
        return Technology(
            name=name,
            category="Web Server",
            version=None,
            confidence=Confidence.MEDIUM,
            evidence=f"Server: {server}",
            source="Server header",
        )
    return None


def _normalize_server_name(raw: str) -> str:
    """Normalize server name to canonical form."""
    mapping = {
        "nginx": "Nginx",
        "apache": "Apache",
        "litespeed": "LiteSpeed",
        "caddy": "Caddy",
        "microsoft-iis": "IIS",
    }
    lower = raw.lower()
    for key, canonical in mapping.items():
        if key in lower:
            return canonical
    return raw.title() if raw else ""


def _parse_powered_by(powered: str) -> Optional[Technology]:
    """Parse X-Powered-By header."""
    php_match = re.search(r"PHP/([\d.]+)", powered, re.I)
    if php_match:
        return Technology(
            name="PHP",
            category="Runtime",
            version=php_match.group(1),
            confidence=Confidence.HIGH,
            evidence=f"X-Powered-By: {powered}",
            source="X-Powered-By",
        )

    # Generic powered-by
    if powered.strip():
        return Technology(
            name=powered.split("/")[0].strip(),
            category="Runtime",
            version=None,
            confidence=Confidence.LOW,
            evidence=f"X-Powered-By: {powered}",
            source="X-Powered-By",
        )
    return None


def _detect_php_html(body: str) -> Optional[Technology]:
    """Detect PHP from HTML body."""
    if ".php" in body or "<?php" in body:
        return Technology(
            name="PHP",
            category="Runtime",
            version=None,
            confidence=Confidence.LOW,
            evidence="HTML evidence",
            source="HTML",
        )
    return None


def _detect_drupal(body: str, headers: dict[str, str]) -> Optional[Technology]:
    """Detect Drupal from HTML and headers."""
    normalized = {k.lower(): v for k, v in headers.items()}
    gen = normalized.get("x-generator", "")
    if "Drupal" in gen:
        match = re.search(r"Drupal\s*([\d.]+)", gen)
        return Technology(
            name="Drupal",
            category="CMS",
            version=match.group(1) if match else None,
            confidence=Confidence.HIGH,
            evidence="X-Generator header",
            source="Header",
        )

    match = re.search(r"Drupal\s*([\d.]+)", body)
    if match:
        return Technology(
            name="Drupal",
            category="CMS",
            version=match.group(1),
            confidence=Confidence.MEDIUM,
            evidence="Drupal.settings / /sites/default/files",
            source="HTML",
        )

    if "Drupal.settings" in body or "/sites/default/files" in body:
        return Technology(
            name="Drupal",
            category="CMS",
            version=None,
            confidence=Confidence.MEDIUM,
            evidence="Drupal signature in HTML",
            source="HTML",
        )
    return None


def _detect_joomla(body: str) -> Optional[Technology]:
    """Detect Joomla from HTML."""
    gen_match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!\s*([\d.]+)?',
        body,
        re.I,
    )
    if gen_match:
        return Technology(
            name="Joomla",
            category="CMS",
            version=gen_match.group(1) or None,
            confidence=Confidence.HIGH,
            evidence="generator metadata",
            source="HTML",
        )
    if "/media/system/js/" in body:
        return Technology(
            name="Joomla",
            category="CMS",
            version=None,
            confidence=Confidence.LOW,
            evidence="HTML signature",
            source="HTML",
        )
    return None


def _detect_laravel(headers: dict[str, str], body: str) -> Optional[Technology]:
    """Detect Laravel from cookie or body."""
    cookies = headers.get("Set-Cookie", "") + headers.get("set-cookie", "")
    if "laravel_session" in cookies:
        return Technology(
            name="Laravel",
            category="Framework",
            version=None,
            confidence=Confidence.HIGH,
            evidence="laravel_session cookie",
            source="Header",
        )
    if "csrf-token" in body.lower() and "laravel" in body.lower():
        return Technology(
            name="Laravel",
            category="Framework",
            version=None,
            confidence=Confidence.MEDIUM,
            evidence="Laravel CSRF token in HTML",
            source="HTML",
        )
    return None


def _detect_django(headers: dict[str, str]) -> Optional[Technology]:
    """Detect Django from cookies."""
    cookies = headers.get("Set-Cookie", "") + headers.get("set-cookie", "")
    if "csrftoken" in cookies or "django" in cookies.lower():
        return Technology(
            name="Django",
            category="Framework",
            version=None,
            confidence=Confidence.MEDIUM,
            evidence="cookie signature",
            source="Header",
        )
    return None


def _detect_node(headers: dict[str, str], body: str) -> Optional[Technology]:
    """Detect Node.js / Express from headers."""
    powered = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")
    if "Express" in powered:
        return Technology(
            name="Node.js",
            category="Runtime",
            version=None,
            confidence=Confidence.HIGH,
            evidence="X-Powered-By Express",
            source="Header",
        )
    return None


def _detect_nextjs(body: str) -> Optional[Technology]:
    """Detect Next.js from HTML body."""
    if "__NEXT_DATA__" in body or "/_next/static" in body:
        return Technology(
            name="Next.js",
            category="Framework",
            version=None,
            confidence=Confidence.HIGH,
            evidence="Next.js asset signature",
            source="HTML",
        )
    return None
