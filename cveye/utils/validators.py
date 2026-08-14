"""Target validation and parsing utilities."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import dns.resolver


HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


@dataclass
class TargetInfo:
    """Validated scan target."""

    input: str
    hostname: Optional[str] = None
    ip: Optional[str] = None
    ips: list[str] | None = None
    is_cidr: bool = False
    is_url: bool = False
    scheme: str = "http"
    port: Optional[int] = None
    path: str = ""

    @property
    def base_url(self) -> str:
        """Return base URL for web scanning."""
        if self.is_url:
            port_part = f":{self.port}" if self.port else ""
            return f"{self.scheme}://{self.hostname}{port_part}{self.path}"
        host = self.hostname or self.ip or self.input
        return f"http://{host}"

    @property
    def scan_host(self) -> str:
        """Return primary scan host."""
        return self.ip or self.hostname or self.input


class TargetValidationError(Exception):
    """Raised when target validation fails."""


def validate_target(target: str) -> TargetInfo:
    """Validate and parse a scan target."""
    target = target.strip()
    if not target:
        raise TargetValidationError("Target cannot be empty")

    # URL
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        if not parsed.hostname:
            raise TargetValidationError(f"Invalid URL: {target}")
        info = TargetInfo(
            input=target,
            hostname=parsed.hostname,
            is_url=True,
            scheme=parsed.scheme,
            port=parsed.port,
            path=parsed.path or "/",
        )
        info.ip = resolve_ip(parsed.hostname)
        return info

    # Single IP address (check before CIDR so "1.2.3.4" is not treated as /32 CIDR)
    try:
        addr = ipaddress.ip_address(target)
        return TargetInfo(
            input=target,
            ip=str(addr),
            hostname=target,
        )
    except ValueError:
        pass

    # CIDR range (must contain '/' to avoid ambiguity)
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            if not ips:
                ips = [str(network.network_address)]
            return TargetInfo(
                input=target,
                ips=ips,
                is_cidr=True,
            )
        except ValueError:
            pass

    # Hostname
    if HOSTNAME_RE.match(target) or "." in target:
        ip = resolve_ip(target)
        return TargetInfo(
            input=target,
            hostname=target,
            ip=ip,
        )

    raise TargetValidationError(f"Invalid target: {target!r}")


def resolve_ip(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        results = dns.resolver.resolve(hostname, "A")
        for r in results:
            return str(r)
    except Exception:
        pass

    # Fallback to socket
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        pass

    return None
