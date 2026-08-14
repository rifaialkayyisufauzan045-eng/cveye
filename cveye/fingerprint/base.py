"""Technology fingerprint detector base."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

from cveye.network.models import Confidence
from cveye.web.models import Technology


@dataclass
class DetectionContext:
    """Context passed to detectors."""

    url: str
    headers: dict[str, str]
    body: str
    banner: Optional[str] = None


class Detector(ABC):
    """Base class for technology detectors."""

    name: str = ""
    category: str = ""

    @abstractmethod
    def detect(self, context: DetectionContext) -> Optional[Technology]:
        """Detect technology from context."""
        ...
