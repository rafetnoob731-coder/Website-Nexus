"""
Website-Nexus — Professional Flask Hosting Panel
=================================================
Developer: VIP DARK GOD
Telegram : @VIP_DARK_GOD
Version   : 5.0 PRO
"""

import os
import re
import io
import json
import time
import uuid
import signal
import shutil
import zipfile
import hashlib
import logging
import datetime
import subprocess
from pathlib import Path
from functools import wraps
from contextlib import suppress
from logging.handlers import RotatingFileHandler

from flask import (
    Flask, render_template, render_template_string,
    request, redirect, url_for, session, jsonify, send_file
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class Config:
    BASE_DIR       = Path(__file__).resolve().parent
    TEMPLATE_DIR   = BASE_DIR / "templates"
    STATIC_DIR     = BASE_DIR / "static"
    UPLOAD_DIR     = BASE_DIR / "uploads"
    LOG_DIR        = BASE_DIR / "logs"
    DB_FILE        = BASE_DIR / "database.json"
    CONFIG_FILE    = BASE_DIR / "config.json"

    SECRET_KEY     = os.environ.get("FLASK_SECRET", "vip_dark_god_nexus_v5")
    ADMIN_PASS     = os.environ.get("ADMIN_PASS", "5656")
    HOST           = os.environ.get("HOST", "0.0.0.0")
    PORT           = int(os.environ.get("PORT", 3522))
    DEBUG          = os.environ.get("DEBUG", "true").lower() == "true"
    LOG_MAX_BYTES  = 5 * 1024 * 1024      # 5 MB per file
    LOG_BACKUP_CNT = 3
    MAX_FILE_SIZE  = 50 * 1024 * 1024      # 50 MB upload limit
    MAX_LOG_LINES  = 2000


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

Config.LOG_DIR.mkdir(parents=True, exist_ok=True)

log_formatter = logging.Formatter(
    "[%(asctime)s] %(levelname)-8s %(name)s :: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

file_handler = RotatingFileHandler(
    Config.LOG_DIR / "panel.log",
    maxBytes=Config.LOG_MAX_BYTES,
    backupCount=Config.LOG_BACKUP_CNT
)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.DEBUG)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(log_formatter)
stream_handler.setLevel(logging.INFO)

logger = logging.getLogger("WebsiteNexus")
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(
    __name__,
    template_folder=str(Config.TEMPLATE_DIR),
    static_folder=str(Config.STATIC_DIR)
)
app.secret_key = Config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = Config.MAX_FILE_SIZE

Config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------

processes: dict[tuple[str, str], subprocess.Popen] = {}
file_handles: dict[tuple[str, str], io.TextIOWrapper] = {}


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _default_db() -> dict:
    return {
        "user_pw": "codex123",
        "users": {},
        "start_times": {},
        "banned_users": [],
        "created_at": int(time.time() * 1000)
    }


def load_db() -> dict:
    if not Config.DB_FILE.exists():
        data = _default_db()
        save_db(data)
        return data
    try:
        data = json.loads(Config.DB_FILE.read_text(encoding="utf-8"))
        for key in ("users", "start_times", "banned_users"):
            data.setdefault(key, {} if key != "banned_users" else [])
        data.setdefault("user_pw", "codex123")
        return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("DB corrupt, resetting: %s", exc)
        data = _default_db()
        save_db(data)
        return data


def save_db(data: dict) -> None:
    tmp = Config.DB_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(Config.DB_FILE)


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

def is_safe_path(basedir: Path, target: Path) -> bool:
    try:
        basedir = basedir.resolve()
        target  = target.resolve()
        return basedir == Path(os.path.commonpath((str(basedir), str(target))))
    except (ValueError, OSError):
        return False


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^\w\-_. ]", "", name)


def hash_ip(ip: str | None) -> str:
    return hashlib.sha256((ip or "unknown").encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def json_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

LOGIN_HTML = (Config.TEMPLATE_DIR / "login.html").read_text(encoding="utf-8") \
    if (Config.TEMPLATE_DIR / "login.html").exists() else ""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_type = request.form.get("login_type", "user")
        username   = sanitize_filename(request.form.get("username", "").strip())
        password   = request.form.get("password", "").strip()
        ip_hash    = hash_ip(request.remote_addr)

        db = load_db()

        if ip_hash in db.get("banned_users", []):
            return render_template_string(
                "<h2 style='color:red;text-align:center;margin-top:4em;'>"
                "You are banned from this panel.</h2>"
            ), 403

        if login_type == "admin":
            if username == "admin" and password == Config.ADMIN_PASS:
                session["is_admin"]  = True
                session["username"]  = "admin"
                session["login_ip"]  = ip_hash
                session.permanent    = True
                logger.info("Admin login from IP hash %s", ip_hash)
                return redirect(url_for("admin_panel"))
            else:
                logger.warning("Failed admin attempt — user=%s ip=%s", username, ip_hash)
        else:
            if username and username not in db["users"] and username != "admin":
                db["users"][username] = db["user_pw"]
                save_db(db)

            if username and password == db["users"].get(username):
                session["is_admin"]  = False
                session["username"]  = username
                session["login_ip"]  = ip_hash
                session.permanent    = True
                logger.info("User login: %s (ip=%s)", username, ip_hash)
                return redirect(url_for("index"))

        return render_template_string(
            LOGIN_HTML +
            "<script>alert('Invalid credentials');</script>"
        )

    return render_template_string(LOGIN_HTML)


@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info("Logout: %s", username)
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

ADMIN_HTML = (Config.TEMPLATE_DIR / "admin.html").read_text(encoding="utf-8") \
    if (Config.TEMPLATE_DIR / "admin.html").exists() else ""


@app.route("/admin")
@admin_required
def admin_panel():
    db = load_db()
    return render_template_string(
        ADMIN_HTML,
        users=db["users"],
        start_times=db["start_times"],
        global_pw=db["user_pw"],
        total_bots=sum(
            1 for p in processes.values()
            if p is not None and p.poll() is None
        )
    )


@app.route("/admin/global_pw", methods=["POST"])
@admin_required
def admin_global_pw():
    db = load_db()
    new_pw = request.form.get("global_pw", "").strip()
    if new_pw:
        db["user_pw"] = new_pw
        save_db(db)
        logger.info("Global password updated by admin")
    return redirect(url_for("admin_panel"))


@app.route("/admin/change_pw", methods=["POST"])
@admin_required
def admin_change_pw():
    db = load_db()
    username = sanitize_filename(request.form.get("username", ""))
    new_pw   = request.form.get("new_pw", "").strip()
    if username in db["users"] and new_pw:
        db["users"][username] = new_pw
        save_db(db)
        logger.info("Password changed for %s by admin", username)
    return redirect(url_for("admin_panel"))


@app.route("/admin/login_as/<username>")
@admin_required
def admin_login_as(username: str):
    username = sanitize_filename(username)
    db = load_db()
    if username in db["users"] or username == "admin":
        session["username"] = username
        session["is_admin"] = False
        logger.info("Admin impersonating %s", username)
    return redirect(url_for("index"))


@app.route("/admin/ban/<username>")
@admin_required
def admin_ban_user(username: str):
    db = load_db()
    username = sanitize_filename(username)
    # Find user's IP from start_times or logs — simplified: just remove user
    ip_from_log = db.get("start_times", {}).get(f"{username}_banned")
    if ip_from_log:
        db.setdefault("banned_users", []).append(ip_from_log)
    if username in db["users"]:
        del db["users"][username]
    save_db(db)
    # Kill all user bots
    keys_to_kill = [k for k in list(processes.keys()) if k[0] == username]
    for key in keys_to_kill:
        _stop_process(key)
    logger.info("User banned & removed: %s", username)
    return redirect(url_for("admin_panel"))


@app.route("/admin/cleanup")
@admin_required
def admin_cleanup():
    """Remove orphaned processes and stale entries."""
    dead_keys = [k for k, p in processes.items() if p is None or p.poll() is not None]
    for k in dead_keys:
        del processes[k]
        file_handles.pop(k, None)
    db = load_db()
    db["start_times"] = {
        k: v for k, v in db["start_times"].items()
        if tuple(k.split("_", 1)) in processes
    }
    save_db(db)
    logger.info("Cleanup removed %d stale entries", len(dead_keys))
    return redirect(url_for("admin_panel"))


# ---------------------------------------------------------------------------
# User dashboard
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    username = session["username"]
    user_dir = Config.UPLOAD_DIR / username
    user_dir.mkdir(exist_ok=True)

    apps = []
    for entry in sorted(user_dir.iterdir()):
        if entry.is_dir():
            p = processes.get((username, entry.name))
            running = p is not None and p.poll() is None
            apps.append({
                "name": entry.name,
                "running": running
            })
    return render_template("dashboard.html", apps=apps, username=username)


# ---------------------------------------------------------------------------
# File management API
# ---------------------------------------------------------------------------

def _user_project_path(username: str, project: str) -> Path:
    return Config.UPLOAD_DIR / username / project / "extracted"


@app.route("/api/list-files/<project>")
@login_required
def api_list_files(project: str):
    extract_dir = _user_project_path(session["username"], project)
    if not is_safe_path(Config.UPLOAD_DIR / session["username"], extract_dir):
        return jsonify({"files": [], "error": "Access denied"}), 403

    files = []
    if extract_dir.exists():
        for path in sorted(extract_dir.rglob("*")):
            if path.is_file():
                files.append(str(path.relative_to(extract_dir)))
    return jsonify({"files": files})


@app.route("/api/read-file", methods=["POST"])
@login_required
@json_required
def api_read_file():
    data = request.json
    project  = sanitize_filename(data.get("project", ""))
    filename = data.get("filename", "")

    base   = Config.UPLOAD_DIR / session["username"]
    target = base / project / "extracted" / filename.lstrip("/")

    if not is_safe_path(base, target) or not target.exists():
        return jsonify({"content": "", "error": "File not found"}), 404

    try:
        content = target.read_text(encoding="utf-8", errors="replace")
        return jsonify({"content": content})
    except Exception as exc:
        return jsonify({"content": "", "error": str(exc)}), 500


@app.route("/api/save-file", methods=["POST"])
@login_required
@json_required
def api_save_file():
    data   = request.json
    project = sanitize_filename(data.get("project", ""))
    filename = data.get("filename", "")

    base   = Config.UPLOAD_DIR / session["username"]
    target = base / project / "extracted" / filename.lstrip("/")

    if not is_safe_path(base, target):
        return jsonify({"status": "error", "error": "Access denied"}), 403

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(data.get("content", ""), encoding="utf-8")
        return jsonify({"status": "success"})
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 500


@app.route("/api/delete-file", methods=["POST"])
@login_required
@json_required
def api_delete_file():
    data = request.json
    project  = sanitize_filename(data.get("project", ""))
    filename = data.get("filename", "")

    base   = Config.UPLOAD_DIR / session["username"]
    target = base / project / "extracted" / filename.lstrip("/")

    if not is_safe_path(base, target) or not target.exists():
        return jsonify({"status": "error", "error": "Not found"}), 404

    target.unlink()
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# Project lifecycle
# ---------------------------------------------------------------------------

def _stop_process(key: tuple[str, str]) -> None:
    p = processes.pop(key, None)
    if p:
        with suppress(Exception):
            if os.name == "nt":
                subprocess.Popen(
                    f"taskkill /F /T /PID {p.pid}",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    fh = file_handles.pop(key, None)
    if fh:
        with suppress(Exception):
            fh.close()


@app.route("/run/<project>")
@login_required
def run_project(project: str):
    username    = session["username"]
    project     = sanitize_filename(project)
    user_dir    = Config.UPLOAD_DIR / username
    app_dir     = user_dir / project
    extract_dir = app_dir / "extracted"

    if not is_safe_path(user_dir, app_dir):
        return redirect(url_for("index"))

    log_path = app_dir / "logs.txt"
    key      = (username, project)

    # Close existing log handle
    if key in file_handles:
        with suppress(Exception):
            file_handles[key].close()

    # If already running do nothing
    if key in processes and processes[key].poll() is None:
        return redirect(url_for("index"))

    if not extract_dir.exists():
        log_path.write_text(
            f"[PANEL ERROR] Extracted directory does not exist: {extract_dir}\n",
            encoding="utf-8"
        )
        return redirect(url_for("index"))

    available = [f.name for f in extract_dir.iterdir() if f.is_file()]
    # Prioritised main file lookup
    main_file = next(
        (f for f in ["main.py", "app.py", "bot.py", "index.js", "server.js", "main.js"]
         if f in available),
        None
    )

    if not main_file:
        log_path.write_text(
            "[PANEL ERROR] No startup file found (main.py / app.py / bot.py / index.js / server.js)\n"
            f"Available: {available}\n",
            encoding="utf-8"
        )
        return redirect(url_for("index"))

    try:
        log_fh = log_path.open("w", encoding="utf-8")
        file_handles[key] = log_fh

        if main_file.endswith(".py"):
            cmd = ["python", "-u", main_file]
        else:
            cmd = ["node", main_file]

        kwargs: dict = {}
        if os.name != "nt":
            kwargs["preexec_fn"] = os.setsid

        processes[key] = subprocess.Popen(
            cmd,
            cwd=str(extract_dir),
            stdout=log_fh,
            stderr=log_fh,
            text=True,
            **kwargs
        )

        log_fh.write(f"[PANEL INFO] Started via: {main_file} (PID: {processes[key].pid})\n\n")
        log_fh.flush()

        db = load_db()
        db["start_times"][f"{username}_{project}"] = int(time.time() * 1000)
        save_db(db)

        logger.info("Project %s/%s started (PID=%d)", username, project, processes[key].pid)

    except Exception as exc:
        log_path.write_text(f"[PANEL ERROR] {exc}\n", encoding="utf-8")
        logger.exception("Start failed %s/%s", username, project)

    return redirect(url_for("index"))


@app.route("/stop/<project>")
@login_required
def stop_project(project: str):
    project = sanitize_filename(project)
    _stop_process((session["username"], project))

    db = load_db()
    db["start_times"].pop(f"{session['username']}_{project}", None)
    save_db(db)
    logger.info("Project %s/%s stopped", session["username"], project)
    return redirect(url_for("index"))


@app.route("/restart/<project>")
@login_required
def restart_project(project: str):
    stop_project(project)
    time.sleep(1)
    return run_project(project)


@app.route("/delete/<project>")
@login_required
def delete_project(project: str):
    username = session["username"]
    project  = sanitize_filename(project)
    _stop_process((username, project))

    app_dir = Config.UPLOAD_DIR / username / project
    if is_safe_path(Config.UPLOAD_DIR / username, app_dir) and app_dir.exists():
        shutil.rmtree(app_dir)
        logger.info("Project %s/%s deleted", username, project)

    db = load_db()
    db["start_times"].pop(f"{username}_{project}", None)
    save_db(db)
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Log viewer
# ---------------------------------------------------------------------------

@app.route("/get-log/<project>")
@login_required
def get_log(project: str):
    username = session["username"]
    project  = sanitize_filename(project)
    app_dir  = Config.UPLOAD_DIR / username / project

    if not is_safe_path(Config.UPLOAD_DIR / username, app_dir):
        return jsonify({"log": "Access denied", "status": "STOPPED", "start_time": 0}), 403

    log_path   = app_dir / "logs.txt"
    log_content = ""
    if log_path.exists():
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        log_content = "\n".join(lines[-Config.MAX_LOG_LINES:])

    p = processes.get((username, project))
    is_running = p is not None and p.poll() is None
    db = load_db()

    return jsonify({
        "log": log_content or "Waiting for logs…",
        "status": "RUNNING" if is_running else "STOPPED",
        "start_time": db["start_times"].get(f"{username}_{project}", 0)
    })


# ---------------------------------------------------------------------------
# File upload / download
# ---------------------------------------------------------------------------

@app.route("/upload", methods=["POST"])
@login_required
def upload_project():
    username = session["username"]
    upload   = request.files.get("file")

    if not upload or not upload.filename.endswith(".zip"):
        return redirect(url_for("index"))

    app_name = sanitize_filename(upload.filename.rsplit(".", 1)[0])
    user_dir = Config.UPLOAD_DIR / username
    app_dir  = user_dir / app_name

    if not is_safe_path(user_dir, app_dir):
        return redirect(url_for("index"))

    app_dir.mkdir(parents=True, exist_ok=True)
    zip_path = app_dir / upload.filename
    upload.save(str(zip_path))

    extract_dir = app_dir / "extracted"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)

    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(str(extract_dir))

    zip_path.unlink()
    logger.info("Uploaded project %s/%s", username, app_name)
    return redirect(url_for("index"))


@app.route("/download/<project>")
@login_required
def download_project(project: str):
    username = session["username"]
    project  = sanitize_filename(project)
    extract_dir = Config.UPLOAD_DIR / username / project / "extracted"

    if not is_safe_path(Config.UPLOAD_DIR / username, extract_dir) or not extract_dir.exists():
        return redirect(url_for("index"))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(extract_dir.rglob("*")):
            if path.is_file():
                zf.write(path, str(path.relative_to(extract_dir)))
    buf.seek(0)
    return send_file(
        buf,
        download_name=f"{project}.zip",
        as_attachment=True,
        mimetype="application/zip"
    )


# ---------------------------------------------------------------------------
# System info (for dashboard)
# ---------------------------------------------------------------------------

@app.route("/api/system-info")
@login_required
def api_system_info():
    import shutil as shutil_mod
    total, used, free = shutil_mod.disk_usage(str(Config.UPLOAD_DIR))
    return jsonify({
        "disk_total": total,
        "disk_used": used,
        "disk_free": free,
        "active_bots": sum(
            1 for p in processes.values()
            if p is not None and p.poll() is None
        ),
        "uptime": int(time.time())
    })


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found", "status": 404}), 404


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large", "status": 413}), 413


@app.errorhandler(500)
def server_error(e):
    logger.exception("Internal server error")
    return jsonify({"error": "Internal server error", "status": 500}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info(
        "Website-Nexus v5.0 PRO starting — Developer: VIP DARK GOD — @VIP_DARK_GOD"
    )
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
