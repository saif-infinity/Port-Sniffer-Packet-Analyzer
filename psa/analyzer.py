"""Live packet capture (Scapy) and protocol analysis.

Capture needs root or CAP_NET_RAW. Decoding is pure Python and works without
privileges, which is what the test suite exercises.
"""

from __future__ import annotations

import itertools
import os
import threading
import time
from collections import Counter, deque
from typing import Any

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, Ether, sniff, wrpcap

SERIES_SECONDS = 600  # how many one-second buckets to keep for the live charts

TCP_FLAG_NAMES = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
}


def _flags_text(flags: Any) -> str:
    return "".join(TCP_FLAG_NAMES.get(ch, ch) + " " for ch in str(flags)).strip()


def decode_packet(pkt, pid: int, ts: float | None = None) -> dict[str, Any]:
    """Turn a Scapy packet into a JSON-friendly record for the UI."""
    record: dict[str, Any] = {
        "id": pid,
        "time": ts if ts is not None else float(pkt.time),
        "length": len(pkt),
        "src": None,
        "dst": None,
        "src_mac": None,
        "dst_mac": None,
        "protocol": "OTHER",
        "sport": None,
        "dport": None,
        "flags": "",
        "info": "",
        "layers": [layer.__name__ for layer in pkt.layers()],
    }

    if pkt.haslayer(Ether):
        record["src_mac"] = pkt[Ether].src
        record["dst_mac"] = pkt[Ether].dst

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        record["protocol"] = "ARP"
        record["src"], record["dst"] = arp.psrc, arp.pdst
        if arp.op == 1:
            record["info"] = f"Who has {arp.pdst}? Tell {arp.psrc}"
        else:
            record["info"] = f"{arp.psrc} is at {arp.hwsrc}"
        return record

    if pkt.haslayer(IP):
        record["src"], record["dst"] = pkt[IP].src, pkt[IP].dst
        record["protocol"] = "IPv4"
    elif pkt.haslayer(IPv6):
        record["src"], record["dst"] = pkt[IPv6].src, pkt[IPv6].dst
        record["protocol"] = "IPv6"

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        record.update(protocol="TCP", sport=tcp.sport, dport=tcp.dport, flags=_flags_text(tcp.flags))
        payload_len = len(bytes(tcp.payload))
        record["info"] = f"{tcp.sport} → {tcp.dport} [{record['flags']}] len={payload_len}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        record.update(protocol="UDP", sport=udp.sport, dport=udp.dport)
        record["info"] = f"{udp.sport} → {udp.dport} len={udp.len}"
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        record["protocol"] = "ICMP"
        record["info"] = f"type={icmp.type} code={icmp.code}"

    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and record["protocol"] in ("UDP", "TCP"):
        qname = pkt[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode(errors="replace")
        record["protocol"] = "DNS"
        record["info"] = f"Query {qname}"

    return record


class CaptureManager:
    """Runs a Scapy sniffer in a background thread and keeps a bounded buffer."""

    def __init__(self, max_packets: int = 5000) -> None:
        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self._records: deque[dict[str, Any]] = deque(maxlen=max_packets)
        self._raw: deque[tuple[int, Any]] = deque(maxlen=max_packets)
        self._arrivals: deque[float] = deque(maxlen=20000)
        self._buckets: deque[dict[str, Any]] = deque(maxlen=SERIES_SECONDS)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.iface: str | None = None
        self.bpf: str | None = None
        self.error: str | None = None
        self.started_at: float | None = None
        self._reset_counters()

    def _reset_counters(self) -> None:
        self.protocols: Counter[str] = Counter()
        self.talkers: Counter[str] = Counter()
        self.flows: Counter[str] = Counter()
        self.total_packets = 0
        self.total_bytes = 0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, iface: str | None = None, bpf: str | None = None) -> None:
        if self.running:
            raise RuntimeError("Capture is already running.")
        with self._lock:
            self._records.clear()
            self._raw.clear()
            self._arrivals.clear()
            self._buckets.clear()
            self._reset_counters()
        self.iface = iface or None
        self.bpf = bpf or None
        self.error = None
        self.started_at = time.time()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="psa-capture", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                sniff(
                    iface=self.iface,
                    filter=self.bpf,
                    prn=self._handle,
                    store=False,
                    timeout=1,
                )
        except Exception as exc:  # permission errors, bad interface, bad BPF filter
            self.error = f"{type(exc).__name__}: {exc}"

    def _handle(self, pkt) -> None:
        with self._lock:
            pid = next(self._ids)
            record = decode_packet(pkt, pid)
            self._records.append(record)
            self._raw.append((pid, pkt))
            self._arrivals.append(time.time())

            self.total_packets += 1
            self.total_bytes += record["length"]
            self.protocols[record["protocol"]] += 1
            if record["src"]:
                self.talkers[record["src"]] += 1
            if record["src"] and record["dst"]:
                if record["sport"] is not None:
                    key = f"{record['src']}:{record['sport']} → {record['dst']}:{record['dport']}"
                else:
                    key = f"{record['src']} → {record['dst']}"
                self.flows[f"{key} ({record['protocol']})"] += 1

            # One bucket per wall-clock second, feeding the real-time charts.
            now_sec = int(time.time())
            if not self._buckets or self._buckets[-1]["t"] != now_sec:
                self._buckets.append({"t": now_sec, "packets": 0, "bytes": 0, "protocols": Counter()})
            bucket = self._buckets[-1]
            bucket["packets"] += 1
            bucket["bytes"] += record["length"]
            bucket["protocols"][record["protocol"]] += 1

    def timeseries(self, window: int = 120) -> dict[str, Any]:
        """Per-second counters for the last `window` seconds, zero-filled for gaps."""
        window = max(1, min(window, SERIES_SECONDS))
        now = int(time.time())
        start = now - window + 1
        with self._lock:
            by_second = {b["t"]: b for b in self._buckets if b["t"] >= start}
            points = []
            for t in range(start, now + 1):
                bucket = by_second.get(t)
                points.append({
                    "t": t,
                    "packets": bucket["packets"] if bucket else 0,
                    "bytes": bucket["bytes"] if bucket else 0,
                    "protocols": dict(bucket["protocols"]) if bucket else {},
                })
        return {"now": now, "window": window, "points": points}

    def packets_since(self, since: int = 0, limit: int = 500) -> list[dict[str, Any]]:
        with self._lock:
            fresh = [r for r in self._records if r["id"] > since]
        return fresh[-limit:]

    def packet_detail(self, pid: int) -> dict[str, Any] | None:
        with self._lock:
            record = next((r for r in self._records if r["id"] == pid), None)
            raw = next((p for i, p in self._raw if i == pid), None)
        if record is None or raw is None:
            return None
        return {**record, "dump": raw.show(dump=True)}

    def stats(self, window: float = 5.0) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            recent = sum(1 for t in self._arrivals if now - t <= window)
            return {
                "running": self.running,
                "iface": self.iface,
                "bpf": self.bpf,
                "error": self.error,
                "started_at": self.started_at,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "distinct_talkers": len(self.talkers),
                "packets_per_sec": round(recent / window, 2),
                "protocols": dict(self.protocols.most_common()),
                "top_talkers": self.talkers.most_common(10),
                "top_flows": self.flows.most_common(10),
            }

    def export_pcap(self, path: str) -> int:
        with self._lock:
            packets = [p for _, p in self._raw]
        wrpcap(path, packets)
        return len(packets)


def list_interfaces() -> list[str]:
    try:
        from scapy.arch import get_if_list

        return sorted(get_if_list())
    except Exception:
        return []


def is_privileged() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0
