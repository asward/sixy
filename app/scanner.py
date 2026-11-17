"""Scan orchestration: detect WAN IP, run nmap (Cloud Run job or locally,
typically inside a VPN container's network), parse, enrich, compare with
Shodan InternetDB, store, and notify on changes."""
import ipaddress
import os
import re
import socket
import subprocess
import threading
import time
import traceback

import requests

from . import store
from .ports import describe, RISK_ORDER

# Env override (mainly SCAN_BACKEND=demo); otherwise the "engine" setting decides.
BACKEND = os.environ.get("SCAN_BACKEND", "")
ENGINES = {"cloudrun": "Google Cloud Run", "local": "Local (via VPN sidecar)", "demo": "Demo"}
_scan_lock = threading.Lock()
state = {"running": False, "next_run": None, "last_error": ""}

IP_SOURCES = ["https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"]


def engine(cfg) -> str:
    return BACKEND or cfg.get("engine") or "cloudrun"


# ---------------- helpers ----------------
def detect_wan_ip(lookup_url: str = "") -> str:
    """Public IP as seen by whatever network this container egresses through."""
    for url in ([lookup_url] if lookup_url else IP_SOURCES):
        try:
            ip = requests.get(url, timeout=8).text.strip()
            if ipaddress.ip_address(ip).is_global:
                return ip
        except Exception:
            continue
    where = lookup_url or "any lookup service"
    raise RuntimeError(f"Could not determine WAN IP from {where}.")


def resolve_target(cfg) -> str:
    """Target to scan: override (IP or DDNS hostname, resolved to an IP) or detected WAN IP."""
    t = (cfg.get("target_override") or "").strip()
    if not t:
        return detect_wan_ip(cfg.get("ip_lookup_url", ""))
    if not re.fullmatch(r"[A-Za-z0-9.\-:]+", t) or t.startswith("-"):
        raise ValueError("Target override must be a plain IP or hostname.")
    try:
        return str(ipaddress.ip_address(t))
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(t, None, socket.AF_INET)[0][4][0]
    except OSError as e:
        raise RuntimeError(f"Could not resolve {t}: {e}") from e


def check_vantage_point(cfg, target):
    """Local engine only: refuse to scan from inside the target network.

    If this container's egress IP equals the target, the scan would either loop
    back through the router (no VPN -> hairpin, misleading results) or the WAN IP
    was detected through the VPN (target = the VPN server)."""
    egress = detect_wan_ip()
    if egress != target:
        return egress
    if cfg.get("target_override"):
        raise RuntimeError(
            f"Sixy's traffic leaves from {egress}, the IP it is about to scan, so it is not behind a VPN "
            "and would scan your network from the inside (NAT hairpin). Run Sixy in the gluetun "
            "container's network (see README).")
    raise RuntimeError(
        f"The detected WAN IP ({egress}) is also the IP Sixy scans from, so it is either the VPN's exit "
        "IP or Sixy isn't behind a VPN. With the local engine, set Target to your DDNS hostname "
        "(or a WAN IP lookup URL that bypasses the VPN), and run Sixy in the gluetun network.")


def _port_args(cfg):
    return {"top100": ["--top-ports", "100"], "all": ["-p-"]}.get(cfg["profile"], ["--top-ports", "1000"])


def nmap_args(cfg, target, scan_type="-sT"):
    args = ["-Pn", scan_type, "-T4", "--max-retries", "2", "--open", "-oG", "-"]
    if scan_type != "-sT":
        args.insert(0, "--privileged")  # file capability cap_net_raw instead of root
    args += _port_args(cfg)
    if cfg.get("version_detect"):
        args += ["-sV", "--version-light"]
    return args + [target]


def udp_ports(cfg):
    return [int(p) for p in cfg.get("udp_ports") or []]


def nmap_udp_args(cfg, target):
    ports = ",".join(str(p) for p in udp_ports(cfg))
    args = ["--privileged", "-Pn", "-sU", "-T4", "--max-retries", "2", "--open", "-oG", "-", "-p", ports]
    if cfg.get("version_detect"):
        args += ["-sV", "--version-light"]
    return args + [target]


# Only "open" counts. UDP "open|filtered" just means no reply, which is what a
# firewalled port (and WireGuard, by design) looks like too.
PORT_RE = re.compile(r"(\d+)/(open)/(tcp|udp)/([^/]*)/([^/]*)/([^/]*)/([^/]*)/")


def parse_greppable(lines):
    ports, seen_ip = {}, None
    for line in lines:
        if not line.startswith("Host: "):
            continue
        seen_ip = line.split()[1]
        seg = next((s for s in line.split("\t") if s.startswith("Ports: ")), "")
        for m in PORT_RE.finditer(seg):
            port, _, proto, _, service, _, version = m.groups()
            ports[(int(port), proto)] = {
                "port": int(port), "proto": proto,
                "service": service.replace("|", "/"), "version": version.replace("|", "/").strip(),
            }
    return seen_ip, sorted(ports.values(), key=lambda p: p["port"])


def internetdb(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"note": "InternetDB lookup needs an IP (target is a hostname)."}
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if r.status_code == 404:
            return {"ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": [], "note": "Not indexed by Shodan."}
        r.raise_for_status()
        return r.json()
    except Exception as e:
        reason = getattr(getattr(e, "response", None), "status_code", None) or type(e).__name__
        return {"error": f"Shodan InternetDB lookup failed ({reason}). Will retry next scan."}


def enrich(ports, allowed, shodan):
    shodan_ports = set(shodan.get("ports") or [])
    for p in ports:
        p.update(describe(p["port"], p["service"]))
        p["allowed"] = p["port"] in allowed
        p["in_shodan"] = p["port"] in shodan_ports
    ports.sort(key=lambda p: (p["allowed"], RISK_ORDER.get(p["risk"], 9), p["port"]))
    return ports


def notify(cfg, title, body):
    urls = [u.strip() for u in (cfg.get("notify_urls") or "").splitlines() if u.strip()]
    if not urls:
        return
    try:
        import apprise
        a = apprise.Apprise()
        for u in urls:
            a.add(u)
        a.notify(title=title, body=body)
    except Exception as e:
        store.add_event("error", f"Notification failed: {e}")


# ---------------- backends ----------------
def _demo_scan(args):
    time.sleep(2)
    t = args[-1]
    return "demo-exec", [
        f"# Nmap 7.95 scan initiated as: nmap {' '.join(args)}",
        f"Host: {t} ()\tStatus: Up",
        f"Host: {t} ()\tPorts: 22/open/tcp//ssh//OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)/, "
        f"443/open/tcp//ssl|http//nginx 1.24.0/, 8123/open/tcp//http//aiohttp 3.9.5 (Python 3.12)/, "
        f"32400/open/tcp//ssl|http//Plex Media Server httpd/\tIgnored State: filtered (996)",
        "# Nmap done at Tue Nov 17 14:00:00 2026 -- 1 IP address (1 host up) scanned in 41.20 seconds",
    ]


def _cloudrun_scan(cfg, target):
    from .gcp import CloudRunScanner
    if not store.key_info():
        raise RuntimeError("No Google service-account key uploaded yet (Settings).")
    sc = CloudRunScanner(store.KEY_PATH, cfg["region"], cfg["job_name"])
    timeout = 3600 if cfg["profile"] == "all" else 900
    exec_name, lines = sc.run_scan(nmap_args(cfg, target), timeout_s=timeout)
    return exec_name, lines, "TCP connect (Cloud Run)"


RAW_DENIED = ("Couldn't open a raw socket", "requires root privileges", "Operation not permitted")
NMAP_BIN = os.environ.get("NMAP_BIN", "nmap")


def _run_nmap(args, timeout):
    try:
        p = subprocess.run([NMAP_BIN, *args], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        raise RuntimeError("nmap is not installed in this container.") from e
    out = p.stdout.splitlines()
    raw_denied = any(m in p.stderr or m in p.stdout for m in RAW_DENIED)
    if p.returncode != 0 and not raw_denied:
        raise RuntimeError(f"nmap exited {p.returncode}: {p.stderr.strip()[-500:]}")
    return out, raw_denied, p.stderr


def _local_scan(cfg, target):
    """nmap inside this container. Prefers SYN + UDP (needs cap_net_raw on the
    nmap binary); falls back to TCP connect if raw sockets are unavailable."""
    timeout = 3 * 3600 if cfg["profile"] == "all" else 1800
    lines, denied, _ = _run_nmap(nmap_args(cfg, target, "-sS"), timeout)
    method = "SYN"
    if denied:
        store.add_event("warn", "Raw sockets unavailable (missing NET_RAW / no-new-privileges?) - "
                                "using TCP connect scan, UDP skipped.")
        lines, _, _ = _run_nmap(nmap_args(cfg, target, "-sT"), timeout)
        return "local", lines, "TCP connect (local)"
    if udp_ports(cfg):
        udp_lines, denied, _ = _run_nmap(nmap_udp_args(cfg, target), 900)
        if not denied:
            lines += udp_lines
            method += " + UDP"
    return "local", lines, f"{method} (local)"


# ---------------- main entry ----------------
def run_scan(trigger="schedule"):
    if not _scan_lock.acquire(blocking=False):
        return None
    state["running"] = True
    cfg = store.load_config()
    scan_id = None
    prev = store.latest_scan()
    try:
        eng = engine(cfg)
        target = resolve_target(cfg)
        scan_id = store.new_scan(target, cfg["profile"])
        if eng == "demo":
            exec_name, lines = _demo_scan(nmap_args(cfg, target))
            method = "Demo data"
        elif eng == "local":
            vantage = check_vantage_point(cfg, target)
            exec_name, lines, method = _local_scan(cfg, target)
            method += f" from {vantage}"
        else:
            exec_name, lines, method = _cloudrun_scan(cfg, target)
        store.update_scan(scan_id, engine=method)
        seen_ip, ports = parse_greppable(lines)
        ip = seen_ip or target
        shodan = internetdb(ip)
        allowed = set(cfg.get("allowed_ports") or [])
        ports = enrich(ports, allowed, shodan)
        unexpected = sorted({p["port"] for p in ports if not p["allowed"]})
        status = "alert" if unexpected else "ok"
        store.update_scan(scan_id, finished=store.now_iso(), ip=ip, status=status, execution=exec_name,
                          ports=ports, unexpected=unexpected, shodan=shodan, raw="\n".join(lines))
        state["last_error"] = ""
        _diff_and_notify(cfg, prev, ip, ports, unexpected, shodan)
        return scan_id
    except Exception as e:
        msg = f"{type(e).__name__}: {e}"
        state["last_error"] = msg
        if scan_id:
            store.update_scan(scan_id, finished=store.now_iso(), status="error", error=msg)
        store.add_event("error", f"Scan failed ({trigger}): {msg}")
        notify(cfg, "WAN scan failed", msg)
        traceback.print_exc()
        return scan_id
    finally:
        state["running"] = False
        _scan_lock.release()


def _diff_and_notify(cfg, prev, ip, ports, unexpected, shodan):
    msgs = []
    open_now = {p["port"] for p in ports}
    if prev:
        if prev["ip"] != ip:
            msgs.append(f"WAN IP changed {prev['ip']} -> {ip}")
        before = {p["port"] for p in prev["ports"]}
        for p in sorted(open_now - before):
            msgs.append(f"NEW open port {p}" + ("" if p in cfg["allowed_ports"] else " (NOT allowed)"))
        for p in sorted(before - open_now):
            msgs.append(f"Port {p} closed")
        new_vulns = set(shodan.get("vulns") or []) - set(prev["shodan"].get("vulns") or [])
        if new_vulns:
            msgs.append("Shodan lists new CVEs: " + ", ".join(sorted(new_vulns)))
    elif unexpected:
        msgs.append("First scan found unexpected ports: " + ", ".join(map(str, unexpected)))

    for m in msgs:
        store.add_event("change", m)
    if msgs or (unexpected and cfg.get("notify_each_alert")):
        lines = msgs or [f"Unexpected open ports on {ip}: {', '.join(map(str, unexpected))}"]
        detail = [f"{p['port']}/{p['proto']} {p['likely']} [{p['risk']}] {p['version']}".strip()
                  for p in ports if not p["allowed"]]
        notify(cfg, f"WAN exposure {'ALERT' if unexpected else 'change'} ({ip})",
               "\n".join(lines + ([""] + detail if detail else [])))


# ---------------- scheduler ----------------
def scheduler_loop():
    last = time.time()
    s = store.latest_scan(finished_only=False)
    if s and s.get("started"):
        from datetime import datetime
        last = datetime.fromisoformat(s["started"]).timestamp()
    while True:
        cfg = store.load_config()
        interval = max(15, int(cfg.get("interval_minutes") or 60)) * 60
        ready = cfg.get("schedule_enabled") and (engine(cfg) != "cloudrun" or cfg.get("job_deployed"))
        state["next_run"] = (last + interval) if ready else None
        if ready and time.time() >= last + interval:
            last = time.time()
            run_scan("schedule")
        time.sleep(20)


def start_scheduler():
    threading.Thread(target=scheduler_loop, daemon=True, name="scheduler").start()


def trigger_now():
    if state["running"]:
        return False
    threading.Thread(target=run_scan, args=("manual",), daemon=True).start()
    return True
