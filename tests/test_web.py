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
                                       "region": "us-west1", "job_name": "sixy-scan",
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


def test_login_flow(client, monkeypatch):
    monkeypatch.setattr(main, "ADMIN_PASSWORD", "s3cret")
    r = client.get("/settings")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert client.get("/api/status").status_code == 401
    assert client.get("/healthz").status_code in (200, 503)  # open by design
    assert client.get("/livez").status_code == 200

    r = client.post("/login", data={"password": "nope", "next": "/settings"})
    assert r.status_code == 200 and "Wrong password" in r.get_data(as_text=True)
    assert client.get("/").status_code == 302

    r = client.post("/login", data={"password": "s3cret", "next": "/settings"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/settings")
    assert client.get("/").status_code == 200
    assert "Log out" in client.get("/").get_data(as_text=True)

    client.get("/logout")
    assert client.get("/").status_code == 302


def test_login_rejects_open_redirect(client, monkeypatch):
    monkeypatch.setattr(main, "ADMIN_PASSWORD", "s3cret")
    r = client.post("/login", data={"password": "s3cret", "next": "//evil.example/x"})
    assert r.headers["Location"] in ("/", "http://localhost/")


def test_basic_auth_still_works_for_scripts(client, monkeypatch):
    monkeypatch.setattr(main, "ADMIN_PASSWORD", "s3cret")
    good = base64.b64encode(b"anyone:s3cret").decode()
    assert client.get("/api/status", headers={"Authorization": f"Basic {good}"}).status_code == 200
    bad = base64.b64encode(b"anyone:wrong").decode()
    assert client.get("/api/status", headers={"Authorization": f"Basic {bad}"}).status_code == 401


@pytest.mark.parametrize("raw,expect", [('"pw"', "pw"), ("'pw'", "pw"), ("  pw ", "pw"), ('"', '"'), ("", "")])
def test_clean_password(raw, expect):
    assert main.clean_password(raw) == expect


def test_reverse_proxy_post_allowed(client):
    r = client.post("/settings", data={"allowed_ports": "443"},
                    headers={"Origin": "https://sixy.example.com", "X-Forwarded-Host": "sixy.example.com"})
    assert r.status_code == 302
    r = client.post("/settings", data={"allowed_ports": "443"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_key_upload_rejects_garbage(client):
    r = client.post("/settings/key", data={"keytext": "not json"})
    assert r.status_code == 302 and store.key_info() is None
