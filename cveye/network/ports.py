"""Port definitions and parsing."""

from __future__ import annotations

from cveye.config import DEFAULT_PORTS


def parse_ports(ports_str: str | None) -> list[int]:
    """Parse comma-separated port list."""
    if not ports_str:
        return list(DEFAULT_PORTS)

    ports: list[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))
