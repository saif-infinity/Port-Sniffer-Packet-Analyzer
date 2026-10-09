"""FastAPI application: REST API for scanning and packet analysis, plus the web UI."""

from __future__ import annotations

import os
import tempfile
import time
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from psa import __version__
from psa.analyzer import CaptureManager, is_privileged, list_interfaces
from psa.scanner import scan_host
from psa.scope import ScopeError, check_target, load_allowed_networks, parse_ports

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="Port Sniffer & Packet Analyzer",
    version=__version__,
    description="Authorised-use TCP port scanner and live packet analyzer.",
)
ALLOWED_NETWORKS = load_allowed_networks()
capture = CaptureManager()


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253, examples=["192.168.1.1", "localhost"])
    ports: str = Field(default="top", max_length=2000, examples=["top", "22,80,8000-8100"])
    timeout: float = Field(default=1.0, ge=0.2, le=10.0)
    concurrency: int = Field(default=300, ge=1, le=1000)
    banners: bool = True


class CaptureStart(BaseModel):
    iface: str | None = Field(default=None, max_length=64)
    bpf: str | None = Field(default=None, max_length=300)


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "privileged": is_privileged(),
        "allowed_networks": [str(n) for n in ALLOWED_NETWORKS],
    }


@app.post("/api/scan")
async def scan(req: ScanRequest) -> dict:
    try:
        addresses = check_target(req.target, ALLOWED_NETWORKS)
    except ScopeError as exc:
        status = 403 if "outside the allowed scope" in str(exc) else 400
        raise HTTPException(status_code=status, detail=str(exc))

    try:
        ports = parse_ports(req.ports)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    host = addresses[0]  # scan the verified address, never a re-resolved name
    started = time.perf_counter()
    results = await scan_host(host, ports, req.timeout, req.banners, req.concurrency)
    duration_ms = round((time.perf_counter() - started) * 1000, 1)

    states = Counter(r.state for r in results)
    return {
        "target": req.target,
        "address": host,
        "addresses": addresses,
        "ports_scanned": len(ports),
        "duration_ms": duration_ms,
        "summary": {
            "open": states.get("open", 0),
            "closed": states.get("closed", 0),
            "filtered": states.get("filtered", 0),
            "error": states.get("error", 0),
        },
        # Closed ports are omitted to keep the response readable; the count is in summary.
        "results": [r.to_dict() for r in results if r.state != "closed"],
    }


@app.get("/api/interfaces")
def interfaces() -> dict:
    return {"interfaces": list_interfaces(), "privileged": is_privileged()}


@app.post("/api/capture/start", status_code=201)
def capture_start(req: CaptureStart) -> dict:
    if capture.running:
        raise HTTPException(status_code=409, detail="Capture is already running.")
    available = list_interfaces()
    if req.iface and available and req.iface not in available:
        raise HTTPException(status_code=400, detail=f"Unknown interface '{req.iface}'.")
    try:
        capture.start(req.iface, req.bpf)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    # Give the sniffer thread a moment to fail fast (permissions, bad BPF filter).
    time.sleep(0.6)
    if capture.error:
        if capture.error.startswith("PermissionError"):
            raise HTTPException(
                status_code=403,
                detail=f"{capture.error}. Run the server as root or grant CAP_NET_RAW (e.g. sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))).",
            )
        raise HTTPException(status_code=500, detail=capture.error)
    return capture.stats()


@app.post("/api/capture/stop")
def capture_stop() -> dict:
    capture.stop()
    return capture.stats()


@app.get("/api/capture/status")
def capture_status() -> dict:
    return capture.stats()


@app.get("/api/capture/timeseries")
def capture_timeseries(window: int = Query(120, ge=10, le=600)) -> dict:
    return capture.timeseries(window)


@app.get("/api/capture/packets")
def capture_packets(since: int = Query(0, ge=0), limit: int = Query(500, ge=1, le=2000)) -> dict:
    return {"packets": capture.packets_since(since, limit)}


@app.get("/api/capture/packets/{pid}")
def capture_packet(pid: int) -> dict:
    detail = capture.packet_detail(pid)
    if detail is None:
        raise HTTPException(status_code=404, detail="Packet not found.")
    return detail


@app.get("/api/capture/export.pcap")
def capture_export() -> FileResponse:
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    capture.export_pcap(path)
    return FileResponse(
        path,
        media_type="application/vnd.tcpdump.pcap",
        filename="capture.pcap",
        background=BackgroundTask(os.unlink, path),
    )


# Mounted last so API routes take precedence.
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="ui")
