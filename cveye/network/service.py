"""Service fingerprinting engine."""

from __future__ import annotations

import re
import socket
import ssl
from typing import Optional

from cveye.network.models import Confidence, PortResult, ServiceFingerprint

# (pattern, product_name, evidence_description)
BANNER_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"SSH-2\.0-OpenSSH[_/ ]([\d.p]+)"), "OpenSSH", "SSH banner"),
    (re.compile(r"OpenSSH[_/ ]([\d.p]+)"), "OpenSSH", "SSH banner"),
    (re.compile(r"SSH-2\.0-([\w.-]+)"), "SSH", "SSH banner"),
    (re.compile(r"220.*(?:ProFTPD|vsftpd|FileZilla)"), "FTP", "FTP banner"),
    (re.compile(r"\+OK.*(?:Dovecot|Courier)"), "POP3", "POP3 banner"),
    (re.compile(r"\* OK.*(?:Dovecot|Courier|imap)", re.I), "IMAP", "IMAP banner"),
    (re.compile(r"Redis server v=([\d.]+)"), "Redis", "Redis banner"),
    (re.compile(r"\x00\x00\x00.*mysql", re.I | re.S), "MySQL", "MySQL banner"),
    (re.compile(r"PostgreSQL", re.I), "PostgreSQL", "PostgreSQL banner"),
    (re.compile(r"Microsoft-IIS/([\d.]+)"), "IIS", "HTTP Server header"),
    (re.compile(r"nginx/([\d.]+)"), "Nginx", "HTTP Server header"),
    (re.compile(r"Apache/([\d.]+)"), "Apache", "HTTP Server header"),
    (re.compile(r"LiteSpeed/([\d.]+)"), "LiteSpeed", "HTTP Server header"),
]

# Common port-to-service hints
PORT_SERVICE_HINTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Attempt to grab service banner."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)

        # Try SSL for known TLS ports
        if port in (443, 8443, 993, 995):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                sock = context.wrap_socket(sock, server_hostname=host)
            except ssl.SSLError:
                pass

        # Send HTTP probe for web ports
        banner = ""
        if port in (80, 443, 8080, 8443):
            probe = b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
            sock.sendall(probe)

        sock.settimeout(2.0)
        try:
            response = sock.recv(1024)
            banner = response.decode("utf-8", errors="replace").strip()
        except (socket.timeout, OSError):
            pass
        sock.close()
        return banner if banner else None
    except Exception:
        return None


def fingerprint_service(
    host: str,
    port_result: PortResult,
    timeout: float = 3.0,
) -> ServiceFingerprint:
    """Fingerprint service on an open port."""
    port = port_result.port
    banner = port_result.banner or grab_banner(host, port, timeout=timeout) or ""
    service = port_result.service or PORT_SERVICE_HINTS.get(port, "unknown")
    product: Optional[str] = None
    version: Optional[str] = None
    evidence: Optional[str] = None
    confidence = Confidence.LOW

    # Banner-based fingerprinting
    for pattern, prod, ev in BANNER_PATTERNS:
        match = pattern.search(banner)
        if match:
            service = prod
            product = prod
            if match.lastindex:
                version = match.group(1)
            confidence = Confidence.HIGH
            evidence = f"{ev}: {banner[:200]}"
            break

    # HTTP Server header extraction
    if not product and "HTTP/" in banner:
        server_match = re.search(r"Server:\s*([^\r\n]+)", banner)
        if server_match:
            server_val = server_match.group(1).strip()
            evidence = f"HTTP Server header: {server_val}"
            # Try to parse name/version
            ver_match = re.search(r"([\w.-]+)/([\d.]+)", server_val)
            if ver_match:
                product = ver_match.group(1)
                version = ver_match.group(2)
                service = "HTTP Server"
                confidence = Confidence.HIGH
            else:
                product = server_val.split("/")[0].strip()
                service = "HTTPS" if port in (443, 8443) else "HTTP Server"
                confidence = Confidence.MEDIUM

    # Fall back to port-based service hint
    if not product and port in PORT_SERVICE_HINTS:
        service = PORT_SERVICE_HINTS[port]
        confidence = Confidence.MEDIUM

    return ServiceFingerprint(
        port=port,
        protocol=port_result.protocol,
        service=service,
        product=product or service,
        version=version or port_result.version,
        banner=banner[:500] if banner else None,
        confidence=confidence,
        evidence=evidence or (banner[:200] if banner else None),
    )
