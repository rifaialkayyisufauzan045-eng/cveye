"""Network port scanner."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from cveye.logger import get_logger
from cveye.network.models import Confidence, NetworkScanResult, PortResult
from cveye.network.ports import parse_ports
from cveye.network.service import fingerprint_service
from cveye.utils.validators import TargetInfo

logger = get_logger()


def scan_port(host: str, port: int, timeout: float) -> Optional[PortResult]:
    """Scan a single TCP port."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        banner = ""
        try:
            sock.settimeout(2)
            data = sock.recv(256)
            banner = data.decode("utf-8", errors="replace").strip()
        except (socket.timeout, OSError):
            pass
        sock.close()
        return PortResult(
            port=port,
            protocol="tcp",
            state="open",
            banner=banner or None,
        )
    except (ConnectionRefusedError, OSError):
        return None


def scan_ports(
    host: str,
    ports: Optional[list[int]] = None,
    ports_str: Optional[str] = None,
    timeout: float = 5.0,
    threads: int = 10,
) -> list[PortResult]:
    """Scan multiple ports concurrently."""
    port_list = ports if ports is not None else parse_ports(ports_str)
    results: list[PortResult] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port
            for port in port_list
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    return sorted(results, key=lambda r: r.port)


def scan_network(
    target: TargetInfo,
    ports_str: Optional[str] = None,
    timeout: float = 5.0,
    threads: int = 10,
) -> list[NetworkScanResult]:
    """Perform network scan on target."""
    # Determine list of hosts to scan
    if target.is_cidr and target.ips:
        hosts = target.ips
    else:
        hosts = [target.scan_host]

    all_results: list[NetworkScanResult] = []

    for host in hosts:
        open_ports = scan_ports(
            host,
            ports_str=ports_str,
            timeout=timeout,
            threads=threads,
        )

        services = []
        for port in open_ports:
            svc = fingerprint_service(host, port, timeout=timeout)
            # Enrich PortResult with service info
            port.service = svc.service
            port.version = svc.version
            port.confidence = svc.confidence
            port.evidence = svc.evidence
            services.append(svc)

        all_results.append(
            NetworkScanResult(
                host=host,
                ip=host,
                hostname=target.hostname if not target.is_cidr else None,
                ports=open_ports,
                services=services,
            )
        )

    return all_results


def _is_ip(value: str) -> bool:
    """Check if value is an IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
