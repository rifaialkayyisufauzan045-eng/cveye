"""HTTP client utilities with rate limiting."""

from __future__ import annotations

import time
from typing import Optional

import httpx


class RateLimitedClient:
    """HTTP client with rate limiting and connection pooling."""

    def __init__(
        self,
        timeout: float = 5.0,
        rate_limit: float = 1.0,
        follow_redirects: bool = True,
    ) -> None:
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.follow_redirects = follow_redirects
        self._client: Optional[httpx.Client] = None
        self._last_request: float = 0.0

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
                headers={"User-Agent": "CVEye/1.0 Scanner"},
            )
        return self._client

    def _wait_rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request
        wait = self.rate_limit - elapsed
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def get(
        self,
        url: str,
        headers: Optional[dict[str, str]] = None,
        **kwargs,
    ) -> httpx.Response:
        """GET request with rate limiting."""
        self._wait_rate_limit()
        client = self._ensure_client()
        return client.get(url, headers=headers or {}, **kwargs)

    def close(self) -> None:
        """Close the underlying client."""
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> RateLimitedClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
