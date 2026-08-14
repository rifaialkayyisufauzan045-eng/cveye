"""CVE product and version matching utilities."""

from __future__ import annotations

import re
from typing import Optional

from packaging.version import InvalidVersion, Version

from cveye.cve.models import (
    CVEFinding,
    CVEStatus,
    SearchConfidence,
    VersionRange,
)
from cveye.network.models import Confidence


def _parse_version(v_str: str) -> Optional[Version]:
    """Safely parse a version string into packaging Version."""
    if not v_str:
        return None
    # Strip leading 'v' or 'V' or spaces
    cleaned = v_str.strip().lstrip("vV")
    # Extract digit pattern if contains extra words
    match = re.search(r"(\d+(?:\.\d+)+)", cleaned)
    if match:
        cleaned = match.group(1)
    try:
        return Version(cleaned)
    except InvalidVersion:
        return None


def verify_product_match(
    finding: CVEFinding,
    expected_vendor: str,
    expected_product: str,
) -> tuple[bool, bool]:
    """
    Verify if finding vendor and product match expected vendor/product.

    Returns tuple (vendor_match, product_match).
    """
    if not expected_product:
        return False, False

    f_vendor = (finding.vendor or "").lower().strip()
    f_product = (finding.product or "").lower().strip()
    e_vendor = (expected_vendor or "").lower().strip()
    e_product = (expected_product or "").lower().strip()

    # Product matching
    product_match = False
    if f_product and e_product:
        product_match = (
            f_product == e_product
            or e_product in f_product
            or f_product in e_product
            or f_product.replace("_", "") == e_product.replace("_", "")
        )
    elif not f_product and finding.description:
        # Fallback check description for product name
        product_match = e_product in finding.description.lower()

    # Vendor matching
    vendor_match = False
    if f_vendor and e_vendor:
        vendor_match = (
            f_vendor == e_vendor
            or e_vendor in f_vendor
            or f_vendor in e_vendor
        )
    elif product_match:
        # If product matches well, assume vendor match ok
        vendor_match = True

    return vendor_match, product_match


def _matches_version_range(ver: Version, vr: VersionRange) -> bool:
    """Check if parsed version fits within a single VersionRange."""
    if vr.start_including:
        v_start_inc = _parse_version(vr.start_including)
        if v_start_inc and ver < v_start_inc:
            return False

    if vr.start_excluding:
        v_start_exc = _parse_version(vr.start_excluding)
        if v_start_exc and ver <= v_start_exc:
            return False

    if vr.end_including:
        v_end_inc = _parse_version(vr.end_including)
        if v_end_inc and ver > v_end_inc:
            return False

    if vr.end_excluding:
        v_end_exc = _parse_version(vr.end_excluding)
        if v_end_exc and ver >= v_end_exc:
            return False

    # Must have at least one bound to be considered a range
    has_bound = any([
        vr.start_including,
        vr.start_excluding,
        vr.end_including,
        vr.end_excluding,
    ])
    return has_bound


def match_cve_status(
    finding: CVEFinding,
    detected_version: Optional[str],
    confidence: Confidence = Confidence.UNKNOWN,
) -> CVEStatus:
    """
    Determine matching CVEStatus for a detected technology version.

    Rule:
    - If detected_version is None / empty / UNKNOWN -> CVEStatus.UNKNOWN
    - If affected_versions range matches detected_version -> AFFECTED
    - If affected_versions exist and version is outside all ranges -> NOT_AFFECTED
    - If affected_versions cannot be parsed or empty -> UNKNOWN or POTENTIALLY_AFFECTED
    """
    if not detected_version or detected_version.upper() == "UNKNOWN":
        return CVEStatus.UNKNOWN

    ver = _parse_version(detected_version)
    if ver is None:
        return CVEStatus.UNKNOWN

    if not finding.affected_versions:
        # Check description or fixed version
        if finding.fixed_version:
            v_fix = _parse_version(finding.fixed_version)
            if v_fix:
                if ver < v_fix:
                    return CVEStatus.AFFECTED
                else:
                    return CVEStatus.NOT_AFFECTED
        return CVEStatus.POTENTIALLY_AFFECTED

    matched_any = False
    has_valid_bounds = False

    for vr in finding.affected_versions:
        has_bound = any([
            vr.start_including,
            vr.start_excluding,
            vr.end_including,
            vr.end_excluding,
        ])
        if has_bound:
            has_valid_bounds = True
            if _matches_version_range(ver, vr):
                matched_any = True
                break

    if matched_any:
        return CVEStatus.AFFECTED
    elif has_valid_bounds:
        return CVEStatus.NOT_AFFECTED
    else:
        return CVEStatus.UNKNOWN


def determine_search_confidence(
    finding: CVEFinding,
    vendor_match: bool,
    product_match: bool,
    version_matched: bool,
    official_source: bool = True,
) -> SearchConfidence:
    """
    Calculate confidence rating (HIGH, MEDIUM, LOW) for CVE findings.

    HIGH:
      Exact product + Exact version + Official source + Affected range confirmed

    MEDIUM:
      Product confirmed + Version confirmed + Affected range partially confirmed

    LOW:
      Search result only + Version correlation incomplete
    """
    if official_source and vendor_match and product_match and version_matched and finding.affected_versions:
        return SearchConfidence.HIGH

    if product_match and version_matched:
        return SearchConfidence.MEDIUM

    return SearchConfidence.LOW
