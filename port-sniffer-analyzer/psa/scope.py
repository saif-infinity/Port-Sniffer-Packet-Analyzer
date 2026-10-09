"""Scope enforcement and port-list parsing.

Scanning is only allowed against addresses inside the configured scope.
By default that is loopback and RFC 1918 / link-local private space, so the
tool works on your own machines and LAN but cannot be pointed at arbitrary
internet hosts. To extend the scope, set the environment variable:

    PSA_ALLOWED_NETWORKS="203.0.113.0/24,2001:db8:1::/48"

Only add networks you own or are explicitly authorised to test.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from ipaddress import IPv4Network, IPv6Network

IPNetwork = IPv4Network | IPv6Network

DEFAULT_NETWORKS = (
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
)

MAX_HOSTNAME_LEN = 253
MAX_PORTS_PER_SCAN = 65535

# Frequently exposed services, used by the "top" preset.
TOP_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2375, 3000, 3306, 3389, 5000, 5432, 5601, 5900,
    5985, 6379, 8000, 8008, 8080, 8443, 8888, 9000, 9200, 27017,
)


class ScopeError(ValueError):
    """Raised when a target is outside the allowed scope or cannot be resolved."""


def load_allowed_networks() -> list[IPNetwork]:
    """Build the allowed network list from defaults plus PSA_ALLOWED_NETWORKS."""
    networks: list[IPNetwork] = [ipaddress.ip_network(n) for n in DEFAULT_NETWORKS]
    extra = os.environ.get("PSA_ALLOWED_NETWORKS", "")
    for item in extra.split(","):
        item = item.strip()
        if item:
            networks.append(ipaddress.ip_network(item, strict=False))
    return networks


def resolve_target(target: str) -> list[str]:
    """Return the IP addresses a target refers to (IP literal or hostname)."""
    target = target.strip()
    if not target or len(target) > MAX_HOSTNAME_LEN:
        raise ScopeError("Target is empty or too long.")

    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"Cannot resolve '{target}': {exc.strerror or exc}") from exc

    addresses = sorted({info[4][0].split("%", 1)[0] for info in infos})
    if not addresses:
        raise ScopeError(f"'{target}' did not resolve to any address.")
    return addresses


def check_target(target: str, networks: list[IPNetwork]) -> list[str]:
    """Resolve the target and verify every resulting address is in scope.

    Returns the verified addresses. Callers must scan these exact addresses
    rather than re-resolving the name, which prevents DNS rebinding tricks.
    """
    addresses = resolve_target(target)
    for address in addresses:
        ip = ipaddress.ip_address(address)
        in_scope = any(ip.version == net.version and ip in net for net in networks)
        if not in_scope:
            raise ScopeError(
                f"{target} resolves to {address}, which is outside the allowed scope. "
                "Add the network to PSA_ALLOWED_NETWORKS if you are authorised to test it."
            )
    return addresses


def parse_ports(spec: str) -> list[int]:
    """Parse a port spec such as '22,80,8000-8100' or the preset 'top'."""
    spec = (spec or "").strip().lower()
    if spec in ("", "top"):
        return list(TOP_PORTS)
    if spec == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        try:
            if "-" in part:
                low_text, high_text = part.split("-", 1)
                low, high = int(low_text), int(high_text)
            else:
                low = high = int(part)
        except ValueError as exc:
            raise ValueError(f"Invalid port expression '{part}'.") from exc
        if not (1 <= low <= high <= 65535):
            raise ValueError(f"Port range '{part}' is out of bounds (1-65535).")
        ports.update(range(low, high + 1))
        if len(ports) > MAX_PORTS_PER_SCAN:
            raise ValueError("Too many ports requested.")

    if not ports:
        raise ValueError("No ports specified.")
    return sorted(ports)
