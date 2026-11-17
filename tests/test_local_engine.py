"""Local engine: nmap inside the container, normally sharing a VPN container's network."""
import http.server
import shutil
import socket
import threading

import pytest

from app import scanner, store


@pytest.fixture
def local_cfg(configured):
    cfg = store.load_config()
    cfg.update(engine="local", udp_ports=[53, 123])
    store.save_config(cfg)
    return cfg


def test_syn_and_udp_args():
    cfg = {"profile": "top100", "version_detect": False, "udp_ports": [53, 123]}
    syn = scanner.nmap_args(cfg, "1.2.3.4", "-sS")
    assert syn[0] == "--privileged" and "-sS" in syn and syn[-1] == "1.2.3.4"
    assert "--privileged" not in scanner.nmap_args(cfg, "1.2.3.4")  # connect scan needs nothing special
    udp = scanner.nmap_udp_args(cfg, "1.2.3.4")
    assert "-sU" in udp and udp[udp.index("-p") + 1] == "53,123"


def test_vantage_point_blocks_hairpin(monkeypatch):
    monkeypatch.setattr(scanner, "detect_wan_ip", lambda url="": "198.51.100.7")
    with pytest.raises(RuntimeError, match="hairpin"):
        scanner.check_vantage_point({"target_override": "198.51.100.7"}, "198.51.100.7")


def test_vantage_point_blocks_autodetected_vpn_ip(monkeypatch):
    monkeypatch.setattr(scanner, "detect_wan_ip", lambda url="": "185.65.1.1")
    with pytest.raises(RuntimeError, match="DDNS"):
        scanner.check_vantage_point({"target_override": ""}, "185.65.1.1")


def test_vantage_point_ok_behind_vpn(monkeypatch):
    monkeypatch.setattr(scanner, "detect_wan_ip", lambda url="": "185.65.1.1")
    assert scanner.check_vantage_point({"target_override": "x"}, "198.51.100.7") == "185.65.1.1"


def test_lookup_url_is_used(monkeypatch):
    seen = []

    class R:
        text = "93.184.216.34\n"

    monkeypatch.setattr(scanner.requests, "get", lambda url, timeout: seen.append(url) or R())
    assert scanner.resolve_target({"target_override": "", "ip_lookup_url": "http://lan/myip"}) == "93.184.216.34"
    assert seen == ["http://lan/myip"]


def test_falls_back_to_connect_scan_without_raw_sockets(local_cfg, monkeypatch):
    calls = []

    def fake(args, timeout):
        calls.append(args)
        if "-sS" in args:
            return [], True, "Couldn't open a raw socket. Error: Operation not permitted (1)"
        return ["Host: 198.51.100.7 ()\tPorts: 22/open/tcp//ssh///", "# Nmap done"], False, ""
    monkeypatch.setattr(scanner, "_run_nmap", fake)
    _, lines, method = scanner._local_scan(local_cfg, "198.51.100.7")
    assert method == "TCP connect (local)"
    assert len(calls) == 2 and "-sT" in calls[1] and not any("-sU" in c for c in calls)
    assert any("Raw sockets unavailable" in e["message"] for e in store.recent_events())


def test_local_run_scan_end_to_end(local_cfg, monkeypatch):
    monkeypatch.setattr(scanner, "BACKEND", "")
    monkeypatch.setattr(scanner, "detect_wan_ip", lambda url="": "185.65.1.1")  # VPN exit

    def fake(args, timeout):
        if "-sU" in args:
            return ["Host: 198.51.100.7 ()\tPorts: 53/open/udp//domain///, 123/open|filtered/udp//ntp///",
                    "# Nmap done"], False, ""
        return ["Host: 198.51.100.7 ()\tPorts: 443/open/tcp//https///, 8006/open/tcp//https///",
                "# Nmap done"], False, ""
    monkeypatch.setattr(scanner, "_run_nmap", fake)
    s = store.get_scan(scanner.run_scan("test"))
    assert s["status"] == "alert", s["error"]
    assert s["engine"] == "SYN + UDP (local) from 185.65.1.1"
    assert s["unexpected"] == [53, 8006]
    assert {(p["port"], p["proto"]) for p in s["ports"]} == {(443, "tcp"), (8006, "tcp"), (53, "udp")}


def test_local_engine_refuses_hairpin_scan(local_cfg, monkeypatch):
    monkeypatch.setattr(scanner, "BACKEND", "")
    monkeypatch.setattr(scanner, "detect_wan_ip", lambda url="": "198.51.100.7")  # no VPN
    monkeypatch.setattr(scanner, "notify", lambda *a: None)
    ran = []
    monkeypatch.setattr(scanner, "_run_nmap", lambda *a: ran.append(a))
    s = store.get_scan(scanner.run_scan("test"))
    assert s["status"] == "error" and "hairpin" in s["error"] and not ran


@pytest.mark.skipif(not shutil.which("nmap"), reason="nmap not installed")
def test_real_nmap_finds_local_listener(local_cfg, monkeypatch):
    srv = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(scanner, "_port_args", lambda cfg: ["-p", str(port)])
    cfg = dict(local_cfg, udp_ports=[], version_detect=False)
    try:
        _, lines, method = scanner._local_scan(cfg, "127.0.0.1")
    finally:
        srv.shutdown()
    _, ports = scanner.parse_greppable(lines)
    assert [p["port"] for p in ports] == [port]
    assert method in ("SYN (local)", "TCP connect (local)")
