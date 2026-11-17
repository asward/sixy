from app.ports import describe
from app.scanner import enrich, nmap_args, parse_greppable, resolve_target

import pytest

REAL_OUTPUT = """\
# Nmap 7.94SVN scan initiated Tue Nov 17 14:40:37 2026 as: nmap -Pn -sT --open -oG - 127.0.0.1
Host: 127.0.0.1 (localhost)\tStatus: Up
Host: 127.0.0.1 (localhost)\tPorts: 8099/open/tcp//unknown///\tIgnored State: closed (100)
# Nmap done at Tue Nov 17 14:40:58 2026 -- 1 IP address (1 host up) scanned in 21.22 seconds
""".splitlines()

VERSIONED = [
    "Host: 203.0.113.5 ()\tPorts: 22/open/tcp//ssh//OpenSSH 9.6p1 Ubuntu (protocol 2.0)/, "
    "443/open/tcp//ssl|http//nginx 1.24.0/, 9000/open/tcp//http//MinIO|Portainer/\tIgnored State: filtered (997)",
    "# Nmap done at x -- 1 IP address (1 host up)",
]


def test_parse_real_nmap_output():
    ip, ports = parse_greppable(REAL_OUTPUT)
    assert ip == "127.0.0.1"
    assert ports == [{"port": 8099, "proto": "tcp", "service": "unknown", "version": ""}]


def test_parse_versions_and_pipe_escaping():
    ip, ports = parse_greppable(VERSIONED)
    assert ip == "203.0.113.5"
    assert [p["port"] for p in ports] == [22, 443, 9000]
    assert ports[1]["service"] == "ssl/http"
    assert ports[2]["version"] == "MinIO/Portainer"
    assert ports[0]["version"].startswith("OpenSSH 9.6p1")


def test_parse_no_open_ports():
    ip, ports = parse_greppable(["Host: 1.2.3.4 ()\tStatus: Up", "# Nmap done at x"])
    assert ip == "1.2.3.4" and ports == []


def test_describe_known_and_fallbacks():
    assert describe(3389)["risk"] == "critical"
    assert describe(49152, "http")["likely"] == "Web service"
    assert describe(2222, "ssh")["likely"].startswith("SSH")
    assert describe(49153, "")["risk"] == "unknown"


def test_enrich_marks_allowed_and_sorts_unexpected_first():
    _, ports = parse_greppable(VERSIONED)
    out = enrich(ports, {443}, {"ports": [443, 22]})
    assert [p["port"] for p in out] == [9000, 22, 443]  # critical, medium, then allowed
    assert out[-1]["allowed"] and out[-1]["in_shodan"]
    assert not out[0]["in_shodan"]


@pytest.mark.parametrize("profile,expect", [("top100", ["--top-ports", "100"]), ("all", ["-p-"]),
                                            ("top1000", ["--top-ports", "1000"])])
def test_nmap_args(profile, expect):
    args = nmap_args({"profile": profile, "version_detect": True}, "1.2.3.4")
    assert args[-1] == "1.2.3.4"
    assert "-sV" in args and "-oG" in args
    assert all(a in args for a in expect)


@pytest.mark.parametrize("bad", ["-oN /etc/passwd", "1.2.3.4; rm -rf /", "--script=x"])
def test_target_override_rejects_injection(bad):
    with pytest.raises(ValueError):
        resolve_target({"target_override": bad})


def test_target_override_resolves_hostname(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, fam: [(fam, 1, 6, "", ("203.0.113.9", 0))])
    assert resolve_target({"target_override": "home.example.duckdns.org"}) == "203.0.113.9"


def test_target_override_ip_passthrough():
    assert resolve_target({"target_override": "198.51.100.7"}) == "198.51.100.7"


def test_parse_ignores_udp_open_filtered():
    _, ports = parse_greppable([
        "Host: 1.2.3.4 ()\tPorts: 53/open/udp//domain//dnsmasq 2.90/, 51820/open|filtered/udp//unknown///, "
        "123/open|filtered/udp//ntp///\tIgnored State: open|filtered (12)"])
    assert [(p["port"], p["proto"]) for p in ports] == [(53, "udp")]
