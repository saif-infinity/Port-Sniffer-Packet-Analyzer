from fastapi.testclient import TestClient

from psa.app import app

client = TestClient(app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_scan_refuses_public_target():
    r = client.post("/api/scan", json={"target": "8.8.8.8", "ports": "80"})
    assert r.status_code == 403


def test_scan_rejects_bad_ports():
    r = client.post("/api/scan", json={"target": "127.0.0.1", "ports": "99999"})
    assert r.status_code == 400


def test_scan_loopback_returns_summary():
    r = client.post("/api/scan", json={"target": "127.0.0.1", "ports": "1-20", "timeout": 0.5, "banners": False})
    assert r.status_code == 200
    body = r.json()
    assert body["ports_scanned"] == 20
    assert set(body["summary"]) == {"open", "closed", "filtered", "error"}


def test_ui_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "Packet Analyzer" in r.text


def test_packets_endpoint_empty():
    r = client.get("/api/capture/packets")
    assert r.status_code == 200
    assert "packets" in r.json()


def test_timeseries_endpoint_shape():
    r = client.get("/api/capture/timeseries?window=60")
    assert r.status_code == 200
    body = r.json()
    assert len(body["points"]) == 60
    assert set(body["points"][0]) == {"t", "packets", "bytes", "protocols"}
    assert client.get("/api/capture/timeseries?window=5").status_code == 422
