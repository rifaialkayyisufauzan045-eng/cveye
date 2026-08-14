"""Configuration management for CVEye."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]

CONFIG_DIR = Path.home() / ".cveye"
CONFIG_FILE = CONFIG_DIR / "config.json"
CACHE_DIR = Path(".cache") / "cve"


@dataclass
class CVEyeConfig:
    """User configuration."""

    nvd_api_key: str = ""
    cache_ttl_hours: int = 24
    default_timeout: float = 5.0
    default_threads: int = 10
    default_rate_limit: float = 1.0
    default_ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    verbose: bool = False

    @classmethod
    def load(cls) -> CVEyeConfig:
        """Load config from file and environment."""
        config = cls()
        config.nvd_api_key = os.environ.get("NVD_API_KEY", "")

        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                for key, value in data.items():
                    if hasattr(config, key):
                        setattr(config, key, value)
            except (json.JSONDecodeError, OSError):
                pass

        if not config.nvd_api_key:
            config.nvd_api_key = os.environ.get("NVD_API_KEY", "")

        return config

    def save(self) -> None:
        """Persist config to disk."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(
            json.dumps(asdict(self), indent=2),
            encoding="utf-8",
        )

    def to_dict(self) -> dict[str, Any]:
        """Return config as dictionary."""
        return asdict(self)
