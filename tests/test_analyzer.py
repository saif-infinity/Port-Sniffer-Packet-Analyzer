from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, TCP, UDP, Ether

from psa.analyzer import CaptureManager, decode_packet


def test_decode_tcp_syn():
    pkt = Ether() / IP(src="192.168.1.5", dst="192.168.1.1") / TCP(sport=51000, dport=443, flags="S")
    rec = decode_packet(pkt, 1, ts=100.0)
    assert rec["protocol"] == "TCP"
    assert rec["src"] == "192.168.1.5" and rec["dst"] == "192.168.1.1"
    assert rec["sport"] == 51000 and rec["dport"] == 443
    assert "SYN" in rec["flags"]
    assert rec["time"] == 100.0
    assert "IP" in rec["layers"] and "TCP" in rec["layers"]


def test_decode_udp_and_dns_query():
    pkt = IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=5353, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="example.com")
    )
    rec = decode_packet(pkt, 2)
    assert rec["protocol"] == "DNS"
    assert "example.com" in rec["info"]


def test_decode_arp_request():
    pkt = Ether() / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.9")
    rec = decode_packet(pkt, 3)
    assert rec["protocol"] == "ARP"
    assert rec["info"].startswith("Who has 192.168.1.9")


def test_decode_icmp_and_ipv6():
    icmp = decode_packet(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(), 4)
    assert icmp["protocol"] == "ICMP"
    v6 = decode_packet(IPv6(src="fd00::1", dst="fd00::2") / UDP(sport=1, dport=2), 5)
    assert v6["protocol"] == "UDP" and v6["src"] == "fd00::1"


def test_capture_manager_buffer_and_stats():
    mgr = CaptureManager(max_packets=3)
    for i in range(5):
        mgr._handle(IP(src=f"10.0.0.{i+1}", dst="10.0.0.99") / TCP(sport=1000 + i, dport=80, flags="S"))
    stats = mgr.stats()
    assert stats["total_packets"] == 5          # counters keep counting
    assert stats["protocols"] == {"TCP": 5}
    assert stats["distinct_talkers"] == 5
    recent = mgr.packets_since(0, 100)
    assert [r["id"] for r in recent] == [3, 4, 5]  # ring buffer keeps the newest
    assert mgr.packets_since(4)[0]["id"] == 5
    detail = mgr.packet_detail(5)
    assert detail and "dump" in detail
    assert mgr.packet_detail(1) is None         # evicted


def test_timeseries_buckets_and_zero_fill():
    mgr = CaptureManager()
    for i in range(4):
        mgr._handle(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i, dport=80, flags="S"))
    mgr._handle(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5, dport=53))

    ts = mgr.timeseries(window=30)
    points = ts["points"]
    assert ts["window"] == 30
    assert len(points) == 30                       # zero-filled to the full window
    assert points[-1]["t"] == ts["now"]            # newest second is last
    assert sum(p["packets"] for p in points) == 5
    assert sum(p["bytes"] for p in points) == sum(
        len(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i, dport=80, flags="S")) for i in range(4)
    ) + len(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5, dport=53))
    merged = {}
    for p in points:
        for k, v in p["protocols"].items():
            merged[k] = merged.get(k, 0) + v
    assert merged == {"TCP": 4, "UDP": 1}


def test_timeseries_cleared_on_restart_and_window_clamped():
    mgr = CaptureManager()
    mgr._handle(IP(src="10.0.0.1", dst="10.0.0.2") / TCP())
    assert sum(p["packets"] for p in mgr.timeseries(60)["points"]) == 1
    mgr._buckets.clear()
    assert all(p["packets"] == 0 for p in mgr.timeseries(60)["points"])
    assert len(mgr.timeseries(10_000)["points"]) == 600   # clamped to SERIES_SECONDS
