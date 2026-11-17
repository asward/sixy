import base64
import hmac
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Flask, Response, flash, jsonify, redirect, render_template, request, url_for

from . import scanner, store

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")


# ---------- auth + basic CSRF guard ----------
@app.before_request
def guard():
    if request.path in ("/healthz",) or request.path.startswith("/static"):
        return None
    if ADMIN_PASSWORD:
        auth = request.headers.get("Authorization", "")
        ok = False
        if auth.startswith("Basic "):
            try:
                _, pw = base64.b64decode(auth[6:]).decode().split(":", 1)
                ok = hmac.compare_digest(pw, ADMIN_PASSWORD)
            except Exception:
                ok = False
        if not ok:
            return Response("Auth required", 401, {"WWW-Authenticate": 'Basic realm="wanwatch"'})
    if request.method == "POST":
        origin = request.headers.get("Origin") or request.headers.get("Referer")
        if origin and urlparse(origin).netloc != request.host:
            return Response("Cross-origin POST rejected", 403)
    return None


@app.template_filter("ago")
def ago(iso):
    if not iso:
        return "-"
    secs = (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds()
    if secs < 90:
        return "just now"
    if secs < 5400:
        return f"{int(secs // 60)} min ago"
    if secs < 172800:
        return f"{int(secs // 3600)} h ago"
    return f"{int(secs // 86400)} d ago"


@app.template_filter("ts")
def ts(epoch):
    if not epoch:
        return "-"
    return datetime.fromtimestamp(epoch, timezone.utc).astimezone().strftime("%H:%M")


def ctx():
    cfg = store.load_config()
    return dict(cfg=cfg, key=store.key_info(), state=scanner.state, backend=scanner.BACKEND)


# ---------- pages ----------
@app.get("/")
def index():
    latest = store.latest_scan()
    current = store.latest_scan(finished_only=False)
    return render_template("index.html", latest=latest, current=current,
                           scans=store.recent_scans(40), events=store.recent_events(20), **ctx())


@app.get("/scan/<int:scan_id>")
def scan_detail(scan_id):
    s = store.get_scan(scan_id)
    if not s:
        return redirect(url_for("index"))
    return render_template("scan.html", s=s, **ctx())


@app.post("/scan")
def scan_now():
    if scanner.trigger_now():
        flash("Scan started. Cloud Run start-up + scan usually takes 1-3 minutes.", "ok")
    else:
        flash("A scan is already running.", "warn")
    return redirect(url_for("index"))


@app.get("/settings")
def settings():
    return render_template("settings.html", **ctx())


@app.post("/settings")
def save_settings():
    cfg = store.load_config()
    f = request.form
    try:
        allowed = sorted({int(p) for p in f.get("allowed_ports", "").replace(",", " ").split() if p})
        if any(not 0 < p < 65536 for p in allowed):
            raise ValueError
    except ValueError:
        flash("Allowed ports must be numbers 1-65535.", "err")
        return redirect(url_for("settings"))
    redeploy = f.get("region") != cfg["region"] or f.get("image") != cfg["image"] or f.get("job_name") != cfg["job_name"]
    cfg.update(
        region=f.get("region", cfg["region"]).strip(),
        job_name=f.get("job_name", cfg["job_name"]).strip(),
        image=f.get("image", cfg["image"]).strip(),
        profile=f.get("profile", "top1000"),
        version_detect=bool(f.get("version_detect")),
        interval_minutes=max(15, int(f.get("interval_minutes") or 60)),
        allowed_ports=allowed,
        target_override=f.get("target_override", "").strip(),
        notify_urls=f.get("notify_urls", "").strip(),
        notify_each_alert=bool(f.get("notify_each_alert")),
        schedule_enabled=bool(f.get("schedule_enabled")),
    )
    if redeploy and cfg.get("job_deployed"):
        cfg["job_deployed"] = False
        flash("Region/image/job name changed - click Deploy again.", "warn")
    store.save_config(cfg)
    flash("Settings saved.", "ok")
    return redirect(url_for("settings"))


@app.post("/settings/key")
def upload_key():
    file = request.files.get("keyfile")
    raw = file.read() if file else request.form.get("keytext", "").encode()
    try:
        info = store.save_key(raw)
    except Exception as e:
        flash(f"Key rejected: {e}", "err")
        return redirect(url_for("settings"))
    cfg = store.load_config()
    cfg["job_deployed"] = False
    store.save_config(cfg)
    store.add_event("setup", f"Service-account key saved for {info['client_email']}")
    flash(f"Key saved for project {info['project_id']}. Now click Deploy.", "ok")
    return redirect(url_for("settings"))


@app.post("/deploy")
def deploy():
    cfg = store.load_config()
    if scanner.BACKEND == "demo":
        cfg["job_deployed"] = True
        store.save_config(cfg)
        flash("Demo mode: nothing deployed.", "ok")
        return redirect(url_for("settings"))
    if not store.key_info():
        flash("Upload a service-account key first.", "err")
        return redirect(url_for("settings"))
    from .gcp import CloudRunScanner
    try:
        sc = CloudRunScanner(store.KEY_PATH, cfg["region"], cfg["job_name"])
        m1 = sc.enable_apis()
        m2 = sc.ensure_job(cfg["image"])
        cfg["job_deployed"] = True
        store.save_config(cfg)
        store.add_event("setup", f"{m1} {m2}")
        flash(f"{m1} {m2}", "ok")
    except Exception as e:
        store.add_event("error", f"Deploy failed: {e}")
        flash(f"Deploy failed: {e}", "err")
    return redirect(url_for("settings"))


# ---------- API ----------
@app.get("/api/status")
def api_status():
    s = store.latest_scan()
    return jsonify({
        "running": scanner.state["running"],
        "last_error": scanner.state["last_error"],
        "latest": s and {k: s[k] for k in ("id", "finished", "ip", "status", "unexpected", "ports")},
    })


@app.get("/healthz")
def healthz():
    """For Uptime Kuma etc.: 200 = clean, 503 = unexpected ports / last scan failed / stale."""
    s = store.latest_scan(finished_only=False)
    if not s or s["status"] == "running":
        s = store.latest_scan() or s
    if not s:
        return jsonify(status="no-scans"), 503
    cfg = store.load_config()
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(s["started"])).total_seconds()
    stale = age > 3 * 60 * cfg["interval_minutes"] + 900
    code = 200 if s["status"] == "ok" and not stale else 503
    return jsonify(status="stale" if stale else s["status"], ip=s["ip"], unexpected=s["unexpected"]), code


def create_app():
    store.init_db()
    scanner.start_scheduler()
    return app
