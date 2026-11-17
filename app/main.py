import base64
import hmac
import logging
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import (Flask, Response, flash, jsonify, redirect, render_template, request, session,
                   url_for)

from . import scanner, store

log = logging.getLogger("sixy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config.update(
    SESSION_COOKIE_NAME="sixy_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)


def clean_password(raw: str) -> str:
    """Compose's list syntax keeps quotes literally (- ADMIN_PASSWORD="x"); strip them."""
    pw = (raw or "").strip()
    if len(pw) >= 2 and pw[0] == pw[-1] and pw[0] in "\"'":
        log.warning("ADMIN_PASSWORD was wrapped in quotes; ignoring the quotes.")
        pw = pw[1:-1]
    return pw


ADMIN_PASSWORD = clean_password(os.environ.get("ADMIN_PASSWORD", ""))
PUBLIC_PATHS = {"/healthz", "/livez", "/login", "/logout"}


def _password_ok(pw: str) -> bool:
    return bool(ADMIN_PASSWORD) and hmac.compare_digest(pw.encode(), ADMIN_PASSWORD.encode())


def _basic_auth_ok() -> bool:
    """Still accepted so scripts/curl can use -u :password."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False
    try:
        _, pw = base64.b64decode(auth[6:]).decode("utf-8", "replace").split(":", 1)
    except Exception:
        return False
    return _password_ok(pw)


def _allowed_hosts():
    hosts = {request.host}
    fwd = request.headers.get("X-Forwarded-Host")
    if fwd:
        hosts.add(fwd.split(",")[0].strip())
    return hosts


# ---------- auth + basic CSRF guard ----------
@app.before_request
def guard():
    if request.method == "POST":
        origin = request.headers.get("Origin") or request.headers.get("Referer")
        if origin and origin != "null" and urlparse(origin).netloc not in _allowed_hosts():
            log.warning("Rejected cross-origin POST to %s from %s (host %s)", request.path, origin, request.host)
            return Response("Cross-origin POST rejected", 403)
    if not ADMIN_PASSWORD or request.path in PUBLIC_PATHS or request.path.startswith("/static"):
        return None
    if session.get("authed") or _basic_auth_ok():
        return None
    if request.path.startswith("/api/"):
        return jsonify(error="login required"), 401
    return redirect(url_for("login", next=request.full_path.rstrip("?")))


@app.context_processor
def auth_ctx():
    return {"auth_enabled": bool(ADMIN_PASSWORD)}


@app.route("/login", methods=["GET", "POST"])
def login():
    nxt = request.values.get("next") or "/"
    if not nxt.startswith("/") or nxt.startswith("//"):
        nxt = "/"
    if not ADMIN_PASSWORD or session.get("authed"):
        return redirect(nxt)
    if request.method == "POST":
        if _password_ok(request.form.get("password", "")):
            session.clear()
            session["authed"] = True
            session.permanent = True
            return redirect(nxt)
        log.warning("Failed login from %s", request.headers.get("X-Forwarded-For", request.remote_addr))
        flash("Wrong password.", "err")
    return render_template("login.html", next=nxt, **ctx())


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/livez")
def livez():
    return "ok"


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
    return dict(cfg=cfg, key=store.key_info(), state=scanner.state, backend=scanner.BACKEND,
                engine=scanner.engine(cfg), engines=scanner.ENGINES)


def _port_list(text):
    ports = sorted({int(p) for p in (text or "").replace(",", " ").split() if p})
    if any(not 0 < p < 65536 for p in ports):
        raise ValueError
    return ports


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
        allowed = _port_list(f.get("allowed_ports", ""))
        udp = _port_list(f.get("udp_ports", "")) if "udp_ports" in f else cfg["udp_ports"]
    except ValueError:
        flash("Ports must be numbers 1-65535.", "err")
        return redirect(url_for("settings"))
    lookup = f.get("ip_lookup_url", cfg.get("ip_lookup_url", "")).strip()
    if lookup and not lookup.startswith(("http://", "https://")):
        flash("WAN IP lookup URL must start with http:// or https://", "err")
        return redirect(url_for("settings"))
    eng = f.get("engine", cfg.get("engine", "cloudrun"))
    if eng not in ("cloudrun", "local"):
        eng = "cloudrun"
    redeploy = any(f.get(k, cfg[k]).strip() != cfg[k] for k in ("region", "image", "job_name"))
    cfg.update(
        engine=eng,
        udp_ports=udp,
        ip_lookup_url=lookup,
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
        "engine": scanner.engine(store.load_config()),
        "latest": s and {k: s.get(k) for k in ("id", "finished", "ip", "status", "engine", "unexpected", "ports")},
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


def _persistent_secret():
    """Keep logins valid across container restarts."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(store.DATA_DIR, "secret.key")
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        key = os.urandom(32)
        os.makedirs(store.DATA_DIR, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        return key


def create_app():
    store.init_db()
    app.secret_key = _persistent_secret()
    if ADMIN_PASSWORD:
        log.info("Login enabled (password is %d characters).", len(ADMIN_PASSWORD))
    else:
        log.warning("ADMIN_PASSWORD not set - the dashboard is open to anyone who can reach it.")
    scanner.start_scheduler()
    return app
