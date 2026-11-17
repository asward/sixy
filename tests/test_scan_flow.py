from app import scanner, store


def test_demo_scan_flags_unexpected_ports(configured):
    scan_id = scanner.run_scan("test")
    s = store.get_scan(scan_id)
    assert s["status"] == "alert"
    assert s["ip"] == "198.51.100.7"
    assert sorted(s["unexpected"]) == [22, 8123]
    assert {p["port"] for p in s["ports"]} == {22, 443, 8123, 32400}
    assert any("unexpected" in e["message"] for e in store.recent_events())


def test_all_allowed_is_ok(configured):
    cfg = store.load_config()
    cfg["allowed_ports"] = [22, 443, 8123, 32400]
    store.save_config(cfg)
    s = store.get_scan(scanner.run_scan("test"))
    assert s["status"] == "ok" and s["unexpected"] == []


def test_change_detection_and_notify(configured, monkeypatch):
    sent = []
    monkeypatch.setattr(scanner, "notify", lambda cfg, title, body: sent.append((title, body)))
    scanner.run_scan("test")
    assert len(sent) == 1  # first scan with unexpected ports

    scanner.run_scan("test")  # identical result -> no notification
    assert len(sent) == 1

    cfg = store.load_config()
    cfg["target_override"] = "198.51.100.8"
    store.save_config(cfg)
    scanner.run_scan("test")
    assert len(sent) == 2 and "198.51.100.8" in sent[-1][0]
    assert any("WAN IP changed" in e["message"] for e in store.recent_events())


def test_failure_is_recorded(configured, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("cloud exploded")
    monkeypatch.setattr(scanner, "_demo_scan", boom)
    monkeypatch.setattr(scanner, "notify", lambda *a: None)
    s = store.get_scan(scanner.run_scan("test"))
    assert s["status"] == "error" and "cloud exploded" in s["error"]
    assert "cloud exploded" in scanner.state["last_error"]


def test_interrupted_scans_are_cleaned_up(data_dir):
    sid = store.new_scan("1.2.3.4", "top100")
    store.init_db()
    assert store.get_scan(sid)["status"] == "error"


def test_key_validation(data_dir):
    import json
    import pytest
    with pytest.raises(ValueError):
        store.save_key(json.dumps({"type": "authorized_user"}).encode())
    assert store.key_info() is None
