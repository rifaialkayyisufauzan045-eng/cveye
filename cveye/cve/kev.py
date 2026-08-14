"""CISA Known Exploited Vulnerabilities catalog integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from cveye.logger import get_logger

logger = get_logger()

KEV_CACHE_FILE = Path(".cache") / "cve" / "kev" / "cisa_kev.json"


class KEVCatalog:
    """Catalog of CISA Known Exploited Vulnerabilities."""

    def __init__(self, cache_file: Optional[Path] = None) -> None:
        self.cache_file = cache_file or KEV_CACHE_FILE
        self._cves: set[str] = set()
        self._load()

    def _load(self) -> None:
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text(encoding="utf-8"))
                for item in data.get("vulnerabilities", []):
                    cve_id = item.get("cveID") or item.get("cve_id")
                    if cve_id:
                        self._cves.add(cve_id.upper())
            except Exception as exc:
                logger.debug("Failed to load KEV catalog: %s", exc)

    def is_known_exploited(self, cve_id: str) -> bool:
        """Check if CVE ID is in CISA KEV catalog."""
        return cve_id.upper() in self._cves
