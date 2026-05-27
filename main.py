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
    request, redirect, url_for, session, jsonify, send_file, flash
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
    API_CREATE_KEY = os.environ.get("API_CREATE_KEY", "Super")


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
        "user_expiry": {},
        "user_created": {},
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
        data.setdefault("user_expiry", {})
        data.setdefault("user_created", {})
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
            user_exists = username in db["users"]
            valid_pw = password == db["users"].get(username) if user_exists else False
            default_pw = db.get("user_pw", "codex123")

            if not user_exists and username and username != "admin":
                if password != default_pw:
                    return render_template_string(
                        LOGIN_HTML +
                        "<script>alert('Invalid credentials');</script>",
                        total_users=len(db.get("users", {}))
                    )
                db["users"][username] = password
                db.setdefault("user_created", {})[username] = int(time.time() * 1000)
                default_days = int(db.get("user_pw_days", 7))
                db.setdefault("user_expiry", {})[username] = int(time.time() * 1000) + (default_days * 86400 * 1000)
                save_db(db)
                valid_pw = True

            if valid_pw:
                db.setdefault("user_last_login", {})[username] = int(time.time() * 1000)
                save_db(db)
                expiry = db.get("user_expiry", {}).get(username)
                if expiry and int(time.time() * 1000) > expiry:
                    return render_template_string(
                        '<h2 style="color:var(--danger);text-align:center;margin-top:4em;font-family:sans-serif;">'
                        'Account expired.<br><small style="color:var(--muted);">Contact admin to renew.</small></h2>'
                    ), 403
                session["is_admin"]  = False
                session["username"]  = username
                session["login_ip"]  = ip_hash
                session.permanent    = True
                logger.info("User login: %s (ip=%s)", username, ip_hash)
                return redirect(url_for("index"))

        return render_template_string(
            LOGIN_HTML +
            "<script>alert('Invalid credentials');</script>",
            total_users=len(db.get("users", {}))
        )

    return render_template_string(LOGIN_HTML, total_users=len(load_db().get("users", {})))


@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info("Logout: %s", username)
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Public API — create user
# ---------------------------------------------------------------------------

@app.route("/create", methods=["GET"])
def api_create_user():
    key = request.args.get("key", "")
    if key != Config.API_CREATE_KEY:
        return jsonify({"error": "Invalid API key"}), 403

    username = sanitize_filename(request.args.get("username", "").strip())
    password = request.args.get("pass", "").strip()
    days_str = request.args.get("day", "7").strip()

    if not username or not password:
        return jsonify({"error": "Missing username or pass"}), 400
    if username == "admin":
        return jsonify({"error": "Cannot create admin"}), 400

    db = load_db()
    if username in db["users"]:
        return jsonify({"error": "User already exists"}), 409

    try:
        days = max(1, int(days_str))
    except ValueError:
        days = 7

    db["users"][username] = password
    db.setdefault("user_created", {})[username] = int(time.time() * 1000)
    db.setdefault("user_expiry", {})[username] = int(time.time() * 1000) + (days * 86400 * 1000)
    save_db(db)

    logger.info("API create user: %s (days=%d)", username, days)
    return jsonify({
        "status": "success",
        "username": username,
        "expiry_days": days,
        "expiry_ms": db["user_expiry"][username]
    })


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

ADMIN_HTML = (Config.TEMPLATE_DIR / "admin.html").read_text(encoding="utf-8") \
    if (Config.TEMPLATE_DIR / "admin.html").exists() else ""


@app.route("/admin")
@admin_required
def admin_panel():
    db = load_db()
    now_ms = int(time.time() * 1000)
    expiry_info = {}
    user_disk = {}
    for u in db.get("users", {}):
        exp = db.get("user_expiry", {}).get(u)
        if exp:
            remaining_days = max(0, int((exp - now_ms) / (86400 * 1000)))
            remaining_hours = max(0, int((exp - now_ms) / (3600 * 1000)))
            expired = now_ms > exp
            expiry_info[u] = {
                "expiry_ms": exp,
                "remaining_days": remaining_days,
                "remaining_hours": remaining_hours,
                "expired": expired
            }
        else:
            expiry_info[u] = None
        udir = Config.UPLOAD_DIR / u
        disk = 0
        if udir.exists():
            for f in udir.rglob("*"):
                if f.is_file():
                    disk += f.stat().st_size
        user_disk[u] = disk

    return render_template_string(
        ADMIN_HTML,
        users=db["users"],
        start_times=db["start_times"],
        global_pw=db["user_pw"],
        total_bots=sum(
            1 for p in processes.values()
            if p is not None and p.poll() is None
        ),
        expiry_info=expiry_info,
        user_created=db.get("user_created", {}),
        user_last_login=db.get("user_last_login", {}),
        user_disk=user_disk,
        now_ms=now_ms
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


@app.route("/admin/add_user", methods=["POST"])
@admin_required
def admin_add_user():
    db = load_db()
    username = sanitize_filename(request.form.get("username", "").strip())
    password = request.form.get("password", "").strip()
    days    = request.form.get("days", "0").strip()

    if not username or not password or username == "admin":
        return redirect(url_for("admin_panel"))

    try:
        days_int = max(0, int(days))
    except ValueError:
        days_int = 0

    db["users"][username] = password
    db["user_created"][username] = int(time.time() * 1000)

    if days_int > 0:
        db["user_expiry"][username] = int(time.time() * 1000) + (days_int * 86400 * 1000)
    else:
        db["user_expiry"].pop(username, None)

    save_db(db)
    logger.info("Admin created user %s (expiry: %d days)", username, days_int)
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
    valid_start_keys = {f"{u}_{p}" for u, p in processes}
    db["start_times"] = {
        k: v for k, v in db["start_times"].items()
        if k in valid_start_keys
    }
    db["process_pids"] = {
        k: v for k, v in db.get("process_pids", {}).items()
        if k in valid_start_keys
    }
    save_db(db)
    logger.info("Cleanup removed %d stale entries", len(dead_keys))
    return redirect(url_for("admin_panel"))


@app.route("/admin/extend_user", methods=["POST"])
@admin_required
def admin_extend_user():
    db = load_db()
    username = sanitize_filename(request.form.get("username", "").strip())
    days = request.form.get("days", "0").strip()
    if username not in db.get("users", {}):
        return redirect(url_for("admin_panel"))
    try:
        days_int = max(1, int(days))
    except ValueError:
        days_int = 1
    now_ms = int(time.time() * 1000)
    current = db.get("user_expiry", {}).get(username, 0)
    if current < now_ms:
        current = now_ms
    db.setdefault("user_expiry", {})[username] = current + (days_int * 86400 * 1000)
    save_db(db)
    logger.info("Extended %s by %d days", username, days_int)
    flash(f"Extended {username} by {days_int} days", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/delete_user/<username>")
@admin_required
def admin_delete_user(username: str):
    db = load_db()
    username = sanitize_filename(username)
    db["users"].pop(username, None)
    db["user_expiry"].pop(username, None)
    db["user_created"].pop(username, None)
    db.setdefault("start_times", {})
    db["start_times"] = {k: v for k, v in db["start_times"].items() if not k.startswith(username + "_")}
    save_db(db)
    user_dir = Config.UPLOAD_DIR / username
    if user_dir.exists() and user_dir.is_dir():
        shutil.rmtree(user_dir, ignore_errors=True)
    logger.info("User deleted permanently: %s", username)
    flash(f"User {username} deleted permanently.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/export")
@admin_required
def admin_export():
    db = load_db()
    import csv
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["username", "password", "created_at", "expiry_ms", "status"])
    now_ms = int(time.time() * 1000)
    for u, pw in db.get("users", {}).items():
        exp = db.get("user_expiry", {}).get(u, 0)
        status = "expired" if exp and now_ms > exp else "active"
        w.writerow([u, pw, db.get("user_created", {}).get(u, ""), exp, status])
    mem = io.BytesIO(buf.getvalue().encode("utf-8-sig"))
    return send_file(mem, download_name="nexus_users.csv", as_attachment=True, mimetype="text/csv")


@app.route("/admin/bulk_create", methods=["POST"])
@admin_required
def admin_bulk_create():
    db = load_db()
    text = request.form.get("bulk", "").strip()
    days = request.form.get("days", "0").strip()
    try:
        days_int = max(0, int(days))
    except ValueError:
        days_int = 0
    count = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        u = sanitize_filename(parts[0])
        pw = parts[1] if len(parts) > 1 else db["user_pw"]
        line_days = parts[2] if len(parts) > 2 else days
        try:
            ld = max(0, int(line_days))
        except ValueError:
            ld = days_int
        if u and u != "admin" and u not in db["users"]:
            db["users"][u] = pw
            db["user_created"][u] = int(time.time() * 1000)
            if ld > 0:
                db.setdefault("user_expiry", {})[u] = int(time.time() * 1000) + (ld * 86400 * 1000)
            count += 1
    save_db(db)
    logger.info("Bulk created %d users", count)
    flash(f"Bulk created {count} users", "success")
    return redirect(url_for("admin_panel"))


@app.route("/api/projects")
@login_required
def api_projects():
    username = session["username"]
    user_dir = Config.UPLOAD_DIR / username
    projects_data = []
    if user_dir.exists():
        for entry in sorted(user_dir.iterdir()):
            if entry.is_dir():
                p = processes.get((username, entry.name))
                running = p is not None and p.poll() is None
                projects_data.append({
                    "name": entry.name,
                    "filename": entry.name,
                    "status": "running" if running else "stopped",
                    "date": datetime.datetime.fromtimestamp(
                        entry.stat().st_mtime
                    ).strftime("%Y-%m-%d %H:%M")
                })
    return jsonify(projects=projects_data)


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
    db = load_db()
    for entry in sorted(user_dir.iterdir()):
        if entry.is_dir():
            p = processes.get((username, entry.name))
            running = p is not None and p.poll() is None
            if not running:
                pid = db.get("process_pids", {}).get(f"{username}_{entry.name}")
                if pid and _is_pid_alive(pid):
                    running = True
            apps.append({
                "name": entry.name,
                "running": running
            })

    # Auto-restart projects that were running but died (Render spin-down recovery)
    for app in apps:
        if not app["running"]:
            db_key = f"{username}_{app['name']}"
            if db.get("process_pids", {}).get(db_key) or db.get("start_times", {}).get(db_key):
                try:
                    _start_project(username, app["name"])
                    app["running"] = True
                except Exception:
                    pass

    disk_bytes = sum(f.stat().st_size for f in user_dir.rglob("*") if f.is_file())
    db = load_db()
    exp_ms = db.get("user_expiry", {}).get(username, 0)
    now_ms = int(time.time() * 1000)

    if exp_ms and exp_ms > now_ms:
        remaining = exp_ms - now_ms
        days = remaining // (86400 * 1000)
        hours = (remaining % (86400 * 1000)) // (3600 * 1000)
        expire_str = f"{days}d {hours}h"
    elif exp_ms and exp_ms <= now_ms:
        expire_str = "Expired"
    else:
        expire_str = "No expiry"

    def fmt_size(b):
        if b < 1024: return f"{b}B"
        elif b < 1024**2: return f"{b/1024:.1f}K"
        elif b < 1024**3: return f"{b/1024**2:.1f}M"
        else: return f"{b/1024**3:.1f}G"

    total_users = len(load_db().get("users", {}))
    return render_template("dashboard.html", apps=apps, username=username,
                           disk_usage=fmt_size(disk_bytes), expire=expire_str,
                           user_count=len(apps), total_users=total_users)


@app.route("/files/<project>")
@login_required
def file_manager(project: str):
    project = sanitize_filename(project)
    extract_dir = Config.UPLOAD_DIR / session["username"] / project / "extracted"
    if not is_safe_path(Config.UPLOAD_DIR / session["username"], extract_dir):
        return redirect(url_for("index"))
    return render_template(
        "files.html",
        project=project,
        username=session["username"]
    )


@app.route("/terminal/<project>")
@login_required
def terminal_page(project: str):
    project = sanitize_filename(project)
    extract_dir = Config.UPLOAD_DIR / session["username"] / project / "extracted"
    if not is_safe_path(Config.UPLOAD_DIR / session["username"], extract_dir):
        return redirect(url_for("index"))
    return render_template(
        "terminal.html",
        project=project,
        username=session["username"]
    )


@app.route("/packages/<project>")
@login_required
def packages_page(project: str):
    project = sanitize_filename(project)
    extract_dir = Config.UPLOAD_DIR / session["username"] / project / "extracted"
    if not is_safe_path(Config.UPLOAD_DIR / session["username"], extract_dir):
        return redirect(url_for("index"))
    return render_template(
        "packages.html",
        project=project,
        username=session["username"]
    )


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

    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()
    return jsonify({"status": "deleted"})


@app.route("/api/create-file", methods=["POST"])
@login_required
@json_required
def api_create_file():
    data = request.json
    project  = sanitize_filename(data.get("project", ""))
    filename = data.get("filename", "")

    base   = Config.UPLOAD_DIR / session["username"]
    target = base / project / "extracted" / filename.lstrip("/")

    if not is_safe_path(base, target):
        return jsonify({"status": "error", "error": "Access denied"}), 403

    if target.exists():
        return jsonify({"status": "error", "error": "Already exists"}), 409

    try:
        if filename.endswith("/") or data.get("type") == "folder":
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("", encoding="utf-8")
        return jsonify({"status": "created"})
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 500


@app.route("/api/rename-file", methods=["POST"])
@login_required
@json_required
def api_rename_file():
    data = request.json
    project   = sanitize_filename(data.get("project", ""))
    old_path  = data.get("oldPath", "")
    new_path  = data.get("newPath", "")

    base   = Config.UPLOAD_DIR / session["username"]
    source = base / project / "extracted" / old_path.lstrip("/")
    dest   = base / project / "extracted" / new_path.lstrip("/")

    if not is_safe_path(base, source) or not is_safe_path(base, dest):
        return jsonify({"status": "error", "error": "Access denied"}), 403

    if not source.exists():
        return jsonify({"status": "error", "error": "Not found"}), 404

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        source.rename(dest)
        return jsonify({"status": "renamed"})
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 500


@app.route("/api/list-tree/<project>")
@login_required
def api_list_tree(project: str):
    extract_dir = _user_project_path(session["username"], project)
    if not is_safe_path(Config.UPLOAD_DIR / session["username"], extract_dir):
        return jsonify({"tree": [], "error": "Access denied"}), 403

    def build_tree(path: Path) -> list:
        items = []
        if not path.exists():
            return items
        for entry in sorted(path.iterdir()):
            item = {"name": entry.name, "type": "folder" if entry.is_dir() else "file"}
            if entry.is_dir():
                item["children"] = build_tree(entry)
            items.append(item)
        return items

    return jsonify({"tree": build_tree(extract_dir)})


# ---------------------------------------------------------------------------
# Project lifecycle
# ---------------------------------------------------------------------------

def _is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False

def _get_process_key(key: tuple[str, str]) -> tuple[str, str]:
    return (key[0], key[1])

def _check_process(key: tuple[str, str]) -> subprocess.Popen | None:
    """Check if process is alive — tries in-memory dict first, then PID from DB."""
    p = processes.get(key)
    if p is not None and p.poll() is None:
        return p
    db = load_db()
    pid = db.get("process_pids", {}).get(f"{key[0]}_{key[1]}")
    if pid and _is_pid_alive(pid):
        return p  # might be None but that's OK — process is alive
    return None

def _stop_process(key: tuple[str, str]) -> None:
    p = processes.pop(key, None)
    pid_to_kill = p.pid if p else None
    if not pid_to_kill:
        db = load_db()
        pid_to_kill = db.get("process_pids", {}).get(f"{key[0]}_{key[1]}")
    if pid_to_kill:
        with suppress(Exception):
            if os.name == "nt":
                subprocess.Popen(
                    f"taskkill /F /T /PID {pid_to_kill}",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:
                try:
                    os.killpg(os.getpgid(pid_to_kill), signal.SIGKILL)
                except ProcessLookupError:
                    os.kill(pid_to_kill, signal.SIGKILL)
        db = load_db()
        db.setdefault("process_pids", {}).pop(f"{key[0]}_{key[1]}", None)
        save_db(db)
    fh = file_handles.pop(key, None)
    if fh:
        with suppress(Exception):
            fh.close()


@app.route("/run/<project>")
@login_required
def run_project(project: str):
    username = session["username"]
    project  = sanitize_filename(project)
    user_dir = Config.UPLOAD_DIR / username
    app_dir  = user_dir / project

    if not is_safe_path(user_dir, app_dir):
        return redirect(url_for("index"))

    key = (username, project)

    # Close existing log handle
    if key in file_handles:
        with suppress(Exception):
            file_handles[key].close()

    # If already running do nothing (check in-memory + DB PID)
    if key in processes and processes[key].poll() is None:
        return redirect(url_for("index"))
    db = load_db()
    pid_check = db.get("process_pids", {}).get(f"{username}_{project}")
    if pid_check and _is_pid_alive(pid_check):
        return redirect(url_for("index"))

    _start_project(username, project)
    return redirect(url_for("index"))


def _start_project(username: str, project: str) -> bool:
    """Start a project as a background process. Returns True on success."""
    project     = sanitize_filename(project)
    user_dir    = Config.UPLOAD_DIR / username
    app_dir     = user_dir / project
    extract_dir = app_dir / "extracted"
    log_path    = app_dir / "logs.txt"
    key         = (username, project)

    if not is_safe_path(user_dir, app_dir):
        return False

    if not extract_dir.exists():
        log_path.write_text(
            f"[PANEL ERROR] Extracted directory does not exist: {extract_dir}\n",
            encoding="utf-8"
        )
        return False

    available = [f.name for f in extract_dir.iterdir() if f.is_file()]
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
        return False

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
        db.setdefault("process_pids", {})[f"{username}_{project}"] = processes[key].pid
        save_db(db)

        logger.info("Project %s/%s started (PID=%d)", username, project, processes[key].pid)
        return True

    except Exception as exc:
        log_path.write_text(f"[PANEL ERROR] {exc}\n", encoding="utf-8")
        logger.exception("Start failed %s/%s", username, project)
        return False


@app.route("/stop/<project>")
@login_required
def stop_project(project: str):
    project = sanitize_filename(project)
    _stop_process((session["username"], project))

    db = load_db()
    db["start_times"].pop(f"{session['username']}_{project}", None)
    db.get("process_pids", {}).pop(f"{session['username']}_{project}", None)
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
    db.get("process_pids", {}).pop(f"{username}_{project}", None)
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
    is_running = (p is not None and p.poll() is None)
    if not is_running:
        db2 = load_db()
        pid = db2.get("process_pids", {}).get(f"{username}_{project}")
        if pid and _is_pid_alive(pid):
            is_running = True
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


@app.route("/api/disk-usage")
@login_required
def api_disk_usage():
    user_dir = Config.UPLOAD_DIR / session["username"]
    total = 0
    for f in user_dir.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return jsonify({"bytes": total})


@app.route("/api/terminal", methods=["POST"])
@login_required
@json_required
def api_terminal():
    data = request.json
    project = sanitize_filename(data.get("project", ""))
    command = data.get("command", "").strip()
    if not command or not project:
        return jsonify({"status": "error", "output": "Missing params"}), 400
    extract_dir = Config.UPLOAD_DIR / session["username"] / project / "extracted"
    if not extract_dir.exists():
        return jsonify({"status": "error", "output": "Project not found"}), 404
    blocked_patterns = [
        r'\brm\s+-[rR]', r'\bmkfs\b', r'\bdd\b', r'\bwget\b', r'\bcurl\b',
        r':\(\)\s*\{', r'\bsudo\b', r'\bsu\b', r'\bchmod\b', r'\bchown\b',
        r'\bpython\s+-[cce]', r'\bnode\s+-e\b', r'\bsh\s+-c\b',
        r'\bbash\s+-c\b', r'\bkill\b', r'\bpasswd\b',
        r'>\s*/dev/', r'\bexport\b',
    ]
    cmd_lower = command.lower()
    for p in blocked_patterns:
        if re.search(p, cmd_lower):
            return jsonify({"status": "error", "output": "Blocked command"}), 403
    try:
        res = subprocess.run(
            ["sh", "-c", command],
            cwd=str(extract_dir),
            capture_output=True,
            text=True,
            timeout=30
        )
        output = res.stdout + res.stderr
        if not output:
            output = "(no output)"
        return jsonify({
            "status": "success" if res.returncode == 0 else "error",
            "output": output[:5000],
            "code": res.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "output": "Command timed out (30s)"}), 504
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)}), 500


@app.route("/api/install-package", methods=["POST"])
@login_required
@json_required
def api_install_package():
    data = request.json
    project = sanitize_filename(data.get("project", ""))
    package = data.get("package", "").strip()
    if not package or not project:
        return jsonify({"status": "error", "error": "Missing params"}), 400
    extract_dir = Config.UPLOAD_DIR / session["username"] / project / "extracted"
    if not extract_dir.exists():
        return jsonify({"status": "error", "error": "Project not found"}), 404
    has_req = (extract_dir / "requirements.txt").exists()
    has_pkg = (extract_dir / "package.json").exists()
    try:
        if has_pkg or package.startswith("npm:"):
            pkg = package.replace("npm:", "")
            cmd = ["npm", "install", pkg] if pkg else ["npm", "install"]
        elif package == "requirements.txt":
            cmd = [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
        else:
            cmd = [sys.executable, "-m", "pip", "install", package]
        res = subprocess.run(cmd, cwd=str(extract_dir), capture_output=True, text=True, timeout=120)
        return jsonify({"status": "success" if res.returncode == 0 else "error", "output": res.stdout + res.stderr})
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "output": "Timeout (120s)"}), 504
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)}), 500


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
