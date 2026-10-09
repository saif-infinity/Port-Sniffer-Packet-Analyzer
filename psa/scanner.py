"""Asynchronous TCP connect scanner with optional banner grabbing."""

from __future__ import annotations

import asyncio
import socket
import time
from contextlib import suppress
from dataclasses import asdict, dataclass

HTTP_LIKE_PORTS = {80, 8000, 8008, 8080, 8888, 5000, 3000, 9000}
MAX_CONCURRENCY = 1000
BANNER_BYTES = 256


@dataclass
class PortResult:
    port: int
    state: str  # open | closed | filtered | error
    service: str | None = None
    banner: str | None = None
    latency_ms: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def service_name(port: int) -> str | None:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return None


def clean_banner(data: bytes) -> str | None:
    """Make untrusted banner bytes safe to display: printable text only, truncated."""
    text = data[:BANNER_BYTES].decode("utf-8", errors="replace")
    # Non-printable bytes (including CR/LF and escape sequences) become spaces, then collapse.
    cleaned = "".join(ch if ch.isprintable() else " " for ch in text)
    cleaned = " ".join(cleaned.split())[:200]
    return cleaned or None


async def _grab_banner(reader, writer, host: str, port: int, timeout: float) -> str | None:
    """Read a greeting banner. For HTTP-like ports, send a harmless HEAD request if silent."""
    budget = min(timeout, 1.5)
    data = b""
    try:
        data = await asyncio.wait_for(reader.read(BANNER_BYTES), budget)
    except (asyncio.TimeoutError, OSError):
        pass
    if not data and port in HTTP_LIKE_PORTS:
        try:
            writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(BANNER_BYTES), budget)
        except (asyncio.TimeoutError, OSError):
            data = b""
    return clean_banner(data)


async def probe_port(
    host: str,
    port: int,
    timeout: float,
    grab_banner: bool,
    semaphore: asyncio.Semaphore,
) -> PortResult:
    async with semaphore:
        started = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except asyncio.TimeoutError:
            return PortResult(port, "filtered", service_name(port))
        except ConnectionRefusedError:
            return PortResult(port, "closed", service_name(port))
        except OSError:
            return PortResult(port, "error", service_name(port))

        latency = round((time.perf_counter() - started) * 1000, 2)
        banner = None
        try:
            if grab_banner:
                banner = await _grab_banner(reader, writer, host, port, timeout)
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
        return PortResult(port, "open", service_name(port), banner, latency)


async def scan_host(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    grab_banner: bool = True,
    concurrency: int = 300,
) -> list[PortResult]:
    """Scan the given ports on one already-validated host address."""
    semaphore = asyncio.Semaphore(max(1, min(concurrency, MAX_CONCURRENCY)))
    tasks = [probe_port(host, p, timeout, grab_banner, semaphore) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted(results, key=lambda r: r.port)
