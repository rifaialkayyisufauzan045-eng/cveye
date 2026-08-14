"""Version parsing and comparison utilities."""

from __future__ import annotations

import re
from typing import Optional

import packaging.version as pkg_version


def normalize_version(ver: str) -> str:
    """Normalize version string for comparison."""
    cleaned = ver.strip().lstrip("vV")
    match = re.search(r"(\d+(?:\.\d+)*)", cleaned)
    if match:
        return match.group(1)
    return cleaned


def parse_version(ver: str) -> Optional[pkg_version.Version]:
    """Parse version string, return None if invalid."""
    if not ver:
        return None
    try:
        return pkg_version.Version(normalize_version(ver))
    except pkg_version.InvalidVersion:
        return None


def compare_versions(v1: str, v2: str) -> int:
    """Compare two versions. Returns -1, 0, or 1."""
    pv1 = parse_version(v1)
    pv2 = parse_version(v2)
    if pv1 is None or pv2 is None:
        return 0
    if pv1 < pv2:
        return -1
    if pv1 > pv2:
        return 1
    return 0


def version_in_range(
    detected: str,
    start_including: Optional[str] = None,
    start_excluding: Optional[str] = None,
    end_including: Optional[str] = None,
    end_excluding: Optional[str] = None,
) -> bool:
    """Check if detected version falls within a range."""
    detected_v = parse_version(detected)
    if detected_v is None:
        return False

    if start_including:
        sv = parse_version(start_including)
        if sv and detected_v < sv:
            return False

    if start_excluding:
        sv = parse_version(start_excluding)
        if sv and detected_v <= sv:
            return False

    if end_including:
        ev = parse_version(end_including)
        if ev and detected_v > ev:
            return False

    if end_excluding:
        ev = parse_version(end_excluding)
        if ev and detected_v >= ev:
            return False

    return True
