import base64

import pytest

from app import main, scanner, store


@pytest.fixture
def client(configured, monkeypatch):
    monkeypatch.setattr(main, "ADMIN_PASSWORD", "")
    main.app.config.update(TESTING=True)
    return main.app.test_client()


def test_pages_render(client):
    assert client.get("/").status_code == 200
    assert client.get("/settings").status_code == 200


def test_healthz_reflects_status(client):
    assert client.get("/healthz").status_code == 503  # no scans
    scanner.run_scan("test")
    r = client.get("/healthz")
    assert r.status_code == 503 and r.get_json()["status"] == "alert"

    cfg = store.load_config()
    cfg["allowed_ports"] = [22, 443, 8123, 32400]
    store.save_config(cfg)
    scanner.run_scan("test")
    assert client.get("/healthz").status_code == 200


def test_dashboard_shows_results(client):
    sid = scanner.run_scan("test")
    html = client.get("/").get_data(as_text=True)
    assert "Home Assistant" in html and "2 unexpected ports" in html
    assert client.get(f"/scan/{sid}").status_code == 200


def test_settings_save_and_validation(client):
    r = client.post("/settings", data={"allowed_ports": "80, 443", "profile": "top100", "interval_minutes": "5",
                                       "region": "us-west1", "job_name": "wanwatch-scan",
                                       "image": "docker.io/instrumentisto/nmap:latest"})
    assert r.status_code == 302
    cfg = store.load_config()
    assert cfg["allowed_ports"] == [80, 443] and cfg["profile"] == "top100"
    assert cfg["interval_minutes"] == 15  # clamped minimum

    client.post("/settings", data={"allowed_ports": "99999"})
    assert store.load_config()["allowed_ports"] == [80, 443]


def test_cross_origin_post_rejected(client):
    r = client.post("/scan", headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_basic_auth(client, monkeypatch):
    monkeypatch.setattr(main, "ADMIN_PASSWORD", "s3cret")
    assert client.get("/").status_code == 401
    good = base64.b64encode(b"admin:s3cret").decode()
    assert client.get("/", headers={"Authorization": f"Basic {good}"}).status_code == 200
    assert client.get("/healthz").status_code in (200, 503)  # unauthenticated by design


def test_key_upload_rejects_garbage(client):
    r = client.post("/settings/key", data={"keytext": "not json"})
    assert r.status_code == 302 and store.key_info() is None
