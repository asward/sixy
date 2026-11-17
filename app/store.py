"""Config file + SQLite history, all under DATA_DIR."""
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

DATA_DIR = os.environ.get("DATA_DIR", "/data")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
KEY_PATH = os.path.join(DATA_DIR, "gcp-key.json")
DB_PATH = os.path.join(DATA_DIR, "sixy.db")

DEFAULTS = {
    "region": "us-west1",
    "job_name": "sixy-scan",
    "image": "docker.io/instrumentisto/nmap:latest",
    "profile": "top1000",          # top100 | top1000 | all
    "version_detect": True,        # nmap -sV
    "interval_minutes": 60,
    "allowed_ports": [],
    "target_override": "",         # blank = auto-detect WAN IP
    "notify_urls": "",             # Apprise URLs, one per line
    "notify_each_alert": False,    # False = only notify on changes
    "schedule_enabled": False,
    "job_deployed": False,
}

_lock = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            cfg.update(json.load(f))
    return cfg


def save_config(cfg: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_PATH)


def save_key(raw: bytes) -> dict:
    info = json.loads(raw)
    for k in ("type", "project_id", "client_email", "private_key"):
        if k not in info:
            raise ValueError(f"Key file is missing '{k}' - upload a service-account JSON key.")
    if info["type"] != "service_account":
        raise ValueError("That is not a service-account key.")
    os.makedirs(DATA_DIR, exist_ok=True)
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return info


def key_info():
    if not os.path.exists(KEY_PATH):
        return None
    with open(KEY_PATH) as f:
        info = json.load(f)
    return {"project_id": info.get("project_id"), "client_email": info.get("client_email")}


def _conn():
    os.makedirs(DATA_DIR, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _lock, _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started TEXT, finished TEXT, ip TEXT, status TEXT,
                profile TEXT, execution TEXT,
                ports_json TEXT DEFAULT '[]', unexpected_json TEXT DEFAULT '[]',
                shodan_json TEXT DEFAULT '{}', raw TEXT DEFAULT '', error TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, kind TEXT, message TEXT
            );
            """
        )
        # A crash mid-scan leaves rows stuck in 'running'.
        c.execute("UPDATE scans SET status='error', error='interrupted (container restart)' WHERE status='running'")


def new_scan(ip, profile) -> int:
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO scans (started, ip, status, profile) VALUES (?,?,?,?)",
            (now_iso(), ip, "running", profile),
        )
        return cur.lastrowid


def update_scan(scan_id, **fields):
    for k in ("ports", "unexpected", "shodan"):
        if k in fields:
            fields[k + "_json"] = json.dumps(fields.pop(k))
    cols = ", ".join(f"{k}=?" for k in fields)
    with _lock, _conn() as c:
        c.execute(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), scan_id))


def _row(r):
    if r is None:
        return None
    d = dict(r)
    d["ports"] = json.loads(d.pop("ports_json") or "[]")
    d["unexpected"] = json.loads(d.pop("unexpected_json") or "[]")
    d["shodan"] = json.loads(d.pop("shodan_json") or "{}")
    return d


def get_scan(scan_id):
    with _conn() as c:
        return _row(c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())


def latest_scan(finished_only=True):
    q = "SELECT * FROM scans WHERE status IN ('ok','alert')" if finished_only else "SELECT * FROM scans"
    with _conn() as c:
        return _row(c.execute(q + " ORDER BY id DESC LIMIT 1").fetchone())


def recent_scans(limit=50):
    with _conn() as c:
        return [_row(r) for r in c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))]


def add_event(kind, message):
    with _lock, _conn() as c:
        c.execute("INSERT INTO events (ts, kind, message) VALUES (?,?,?)", (now_iso(), kind, message))


def recent_events(limit=30):
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]
