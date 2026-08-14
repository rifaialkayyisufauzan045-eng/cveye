"""WordPress detection and plugin/theme enumeration."""

from __future__ import annotations

import re
from typing import Optional

from bs4 import BeautifulSoup

from cveye.network.models import Confidence
from cveye.web.models import Technology


def detect_wordpress(
    html: str,
    headers: dict[str, str],
    base_url: str,
) -> tuple[Optional[Technology], list[Technology], list[Technology]]:
    """Detect WordPress and plugins/themes from public page content."""
    plugins: list[Technology] = []
    themes: list[Technology] = []
    wp_detected = False
    version: Optional[str] = None
    confidence = Confidence.LOW
    evidence: Optional[str] = None

    # Generator meta tag
    gen_match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]+)?',
        html,
        re.I,
    )
    if gen_match:
        wp_detected = True
        version = gen_match.group(1) or None
        confidence = Confidence.HIGH
        evidence = "generator metadata"

    # HTML signatures
    signatures = [
        ("/wp-content/", "wp-content path"),
        ("/wp-includes/", "wp-includes path"),
        ("wp-login.php", "wp-login"),
        ("WordPress", "WordPress text"),
    ]
    for sig, ev in signatures:
        if sig in html:
            wp_detected = True
            if confidence == Confidence.LOW:
                confidence = Confidence.MEDIUM
                evidence = ev

    # Plugin detection via asset URLs
    plugin_pattern = re.compile(
        r"/wp-content/plugins/([\w-]+)/(?:.*?ver=([\d.]+))?",
        re.I,
    )
    seen_plugins: set[str] = set()
    for match in plugin_pattern.finditer(html):
        plugin_name = match.group(1)
        plugin_version = match.group(2) or None
        # Normalize plugin name: replace hyphens/underscores with spaces, title case
        display_name = plugin_name.replace("-", " ").replace("_", " ").title()
        key = plugin_name.lower()
        if key not in seen_plugins:
            seen_plugins.add(key)
            plugins.append(
                Technology(
                    name=display_name,
                    category="WordPress Plugin",
                    version=plugin_version,
                    confidence=Confidence.MEDIUM,
                    evidence=f"wp-content/plugins/{plugin_name}",
                    source="HTML",
                )
            )

    # Theme detection
    theme_pattern = re.compile(r"/wp-content/themes/([\w-]+)/", re.I)
    seen_themes: set[str] = set()
    for match in theme_pattern.finditer(html):
        theme_name = match.group(1)
        display_name = theme_name.replace("-", " ").replace("_", " ").title()
        key = theme_name.lower()
        if key not in seen_themes:
            seen_themes.add(key)
            themes.append(
                Technology(
                    name=display_name,
                    category="WordPress Theme",
                    version=None,
                    confidence=Confidence.LOW,
                    evidence=f"wp-content/themes/{theme_name}",
                    source="HTML",
                )
            )

    if not wp_detected:
        return None, plugins, themes

    wp_tech = Technology(
        name="WordPress",
        category="CMS",
        version=version,
        confidence=confidence,
        evidence=evidence,
        source="HTML",
    )
    return wp_tech, plugins, themes
