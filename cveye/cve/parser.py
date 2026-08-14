"""Parse CVE search results and source pages."""

from __future__ import annotations

import re
from typing import Any, Optional

from bs4 import BeautifulSoup

from cveye.cve.cvss import score_to_severity
from cveye.cve.models import CVEFinding, CVEWebResult, Severity, VersionRange

CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def extract_cve_ids(text: str) -> list[str]:
    """Extract unique CVE IDs from text."""
    seen: set[str] = set()
    ids: list[str] = []
    for match in CVE_ID_PATTERN.finditer(text):
        cve_id = match.group(0).upper()
        if cve_id not in seen:
            seen.add(cve_id)
            ids.append(cve_id)
    return ids


def parse_nvd_search_results(html: str) -> list[dict[str, str]]:
    """Parse NVD search results page."""
    results: list[dict[str, str]] = []
    soup = BeautifulSoup(html, "html.parser")

    # NVD result rows
    for row in soup.select("table.table-striped tbody tr"):
        link = row.select_one("a[href*='/vuln/detail/CVE-']")
        if not link:
            continue
        href = link.get("href", "")
        cve_id = link.get_text(strip=True).upper()
        if not CVE_ID_PATTERN.match(cve_id):
            cve_match = CVE_ID_PATTERN.search(href)
            if cve_match:
                cve_id = cve_match.group(0).upper()
            else:
                continue

        snippet_el = row.select_one("p") or row.select_one("span")
        snippet = snippet_el.get_text(strip=True)[:300] if snippet_el else ""
        title = snippet[:120] if snippet else cve_id

        url = href if href.startswith("http") else f"https://nvd.nist.gov{href}"
        results.append({
            "cve_id": cve_id,
            "title": title,
            "url": url,
            "source": "NVD",
            "snippet": snippet,
        })

    # Fallback: extract CVE links from full page
    if not results:
        for link in soup.select("a[href*='CVE-']"):
            href = link.get("href", "")
            match = CVE_ID_PATTERN.search(href) or CVE_ID_PATTERN.search(link.get_text())
            if not match:
                continue
            cve_id = match.group(0).upper()
            url = href if href.startswith("http") else f"https://nvd.nist.gov{href}"
            results.append({
                "cve_id": cve_id,
                "title": cve_id,
                "url": url,
                "source": "NVD",
                "snippet": "",
            })

    # Deduplicate
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for r in results:
        if r["cve_id"] not in seen:
            seen.add(r["cve_id"])
            unique.append(r)
    return unique


def parse_discovery_results(html: str) -> list[dict[str, str]]:
    """Parse DuckDuckGo HTML search results for CVE links."""
    results: list[dict[str, str]] = []
    soup = BeautifulSoup(html, "html.parser")

    for link in soup.select("a.result__a, a.result-link"):
        href = link.get("href", "")
        title = link.get_text(strip=True)
        snippet_el = link.find_parent("div")
        snippet = ""
        if snippet_el:
            sn = snippet_el.select_one(".result__snippet")
            snippet = sn.get_text(strip=True)[:300] if sn else ""

        cve_ids = extract_cve_ids(f"{title} {href} {snippet}")
        for cve_id in cve_ids:
            source = "NVD" if "nvd.nist.gov" in href else "CVE.org" if "cve.org" in href else "Search"
            url = href if href.startswith("http") else f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            results.append({
                "cve_id": cve_id,
                "title": title or cve_id,
                "url": url,
                "source": source,
                "snippet": snippet,
            })

    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for r in results:
        if r["cve_id"] not in seen:
            seen.add(r["cve_id"])
            unique.append(r)
    return unique


def parse_nvd_cve_page(html: str, cve_id: str) -> Optional[CVEFinding]:
    """Parse NVD CVE detail page into CVEFinding."""
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)

    # Description
    description = ""
    desc_el = soup.select_one("#vulnDescriptionTitle + p, [data-testid='vuln-description']")
    if desc_el:
        description = desc_el.get_text(strip=True)
    else:
        for p in soup.select("p"):
            t = p.get_text(strip=True)
            if len(t) > 50:
                description = t[:500]
                break

    # CVSS score
    cvss_score: Optional[float] = None
    cvss_match = re.search(r"Base Score:\s*([\d.]+)", text)
    if not cvss_match:
        cvss_match = re.search(r"CVSS\s*(?:Base\s*)?Score[:\s]+([\d.]+)", text, re.I)
    if cvss_match:
        try:
            cvss_score = float(cvss_match.group(1))
        except ValueError:
            pass

    # CWE
    cwes: list[str] = []
    for match in re.finditer(r"CWE-\d+", text):
        cwe = match.group(0)
        if cwe not in cwes:
            cwes.append(cwe)

    # Vendor / product from CPE
    vendor = ""
    product = ""
    affected_ranges: list[VersionRange] = []
    fixed_version: Optional[str] = None

    for row in soup.select("#vulnConfigurationsTable tbody tr, table tbody tr"):
        cells = row.select("td")
        if len(cells) < 2:
            continue
        cpe_text = cells[0].get_text(strip=True)
        if "cpe:" not in cpe_text.lower():
            continue

        parts = cpe_text.split(":")
        if len(parts) >= 5:
            vendor = vendor or parts[3]
            product = product or parts[4]

        # Version range from row text
        row_text = row.get_text(" ", strip=True)
        vr = _parse_version_range_from_text(row_text)
        if vr:
            affected_ranges.append(vr)
            if vr.end_excluding:
                fixed_version = fixed_version or vr.end_excluding

    # References
    references: list[str] = []
    for link in soup.select("a[href]"):
        href = link.get("href", "")
        if href.startswith("http") and "nvd.nist.gov" not in href:
            if href not in references:
                references.append(href)

    if not description and not cvss_score:
        return None

    return CVEFinding(
        cve_id=cve_id.upper(),
        vendor=vendor,
        product=product,
        description=description,
        cvss_score=cvss_score,
        severity=score_to_severity(cvss_score),
        cwe=cwes[:5],
        affected_versions=affected_ranges,
        fixed_version=fixed_version,
        references=references[:10],
        source="NVD",
    )


def _parse_version_range_from_text(text: str) -> Optional[VersionRange]:
    """Extract version range from CPE configuration text."""
    vr = VersionRange()

    patterns = [
        (r"From \(including\)\s*([\d.]+)", "start_including"),
        (r"From \(excluding\)\s*([\d.]+)", "start_excluding"),
        (r"Up to \(including\)\s*([\d.]+)", "end_including"),
        (r"Up to \(excluding\)\s*([\d.]+)", "end_excluding"),
        (r"versionStartIncluding[=:\s]+([\d.]+)", "start_including"),
        (r"versionEndExcluding[=:\s]+([\d.]+)", "end_excluding"),
    ]

    for pattern, field in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            setattr(vr, field, match.group(1))

    if any([vr.start_including, vr.start_excluding, vr.end_including, vr.end_excluding]):
        return vr
    return None


def web_result_from_dict(data: dict[str, str]) -> CVEWebResult:
    """Convert raw search dict to CVEWebResult."""
    return CVEWebResult(
        cve_id=data.get("cve_id", ""),
        title=data.get("title", ""),
        url=data.get("url", ""),
        source=data.get("source", ""),
        snippet=data.get("snippet", ""),
    )


def web_result_to_dict(result: CVEWebResult) -> dict[str, str]:
    return {
        "cve_id": result.cve_id,
        "title": result.title,
        "url": result.url,
        "source": result.source,
        "snippet": result.snippet,
    }
