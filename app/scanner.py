"""Scan orchestration: detect WAN IP, run nmap in Cloud Run, parse, enrich,
compare with Shodan InternetDB, store, and notify on changes."""
import ipaddress
import os
import re
import threading
import time
import traceback

import requests

from . import store
from .ports import describe, RISK_ORDER

BACKEND = os.environ.get("SCAN_BACKEND", "cloudrun")  # cloudrun | demo
_scan_lock = threading.Lock()
state = {"running": False, "next_run": None, "last_error": ""}

IP_SOURCES = ["https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"]


# ---------------- helpers ----------------
def detect_wan_ip() -> str:
    for url in IP_SOURCES:
        try:
            ip = requests.get(url, timeout=8).text.strip()
            if ipaddress.ip_address(ip).is_global:
                return ip
        except Exception:
            continue
    raise RuntimeError("Could not determine WAN IP from any lookup service.")


def resolve_target(cfg) -> str:
    t = (cfg.get("target_override") or "").strip()
    if not t:
        return detect_wan_ip()
    if not re.fullmatch(r"[A-Za-z0-9.\-:]+", t) or t.startswith("-"):
        raise ValueError("Target override must be a plain IP or hostname.")
    return t


def nmap_args(cfg, target):
    args = ["-Pn", "-sT", "-T4", "--max-retries", "2", "--open", "-oG", "-"]
    args += {"top100": ["--top-ports", "100"], "all": ["-p-"]}.get(cfg["profile"], ["--top-ports", "1000"])
    if cfg.get("version_detect"):
        args += ["-sV", "--version-light"]
    return args + [target]


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


def _cloudrun_scan(cfg, args):
    from .gcp import CloudRunScanner
    if not store.key_info():
        raise RuntimeError("No Google service-account key uploaded yet (Settings).")
    sc = CloudRunScanner(store.KEY_PATH, cfg["region"], cfg["job_name"])
    timeout = 3600 if cfg["profile"] == "all" else 900
    return sc.run_scan(args, timeout_s=timeout)


# ---------------- main entry ----------------
def run_scan(trigger="schedule"):
    if not _scan_lock.acquire(blocking=False):
        return None
    state["running"] = True
    cfg = store.load_config()
    scan_id = None
    prev = store.latest_scan()
    try:
        target = resolve_target(cfg)
        scan_id = store.new_scan(target, cfg["profile"])
        args = nmap_args(cfg, target)
        exec_name, lines = _demo_scan(args) if BACKEND == "demo" else _cloudrun_scan(cfg, args)
        seen_ip, ports = parse_greppable(lines)
        ip = seen_ip or target
        shodan = internetdb(ip)
        allowed = set(cfg.get("allowed_ports") or [])
        ports = enrich(ports, allowed, shodan)
        unexpected = [p["port"] for p in ports if not p["allowed"]]
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
        ready = cfg.get("schedule_enabled") and (BACKEND == "demo" or cfg.get("job_deployed"))
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
