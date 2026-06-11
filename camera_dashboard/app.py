from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, stream_with_context
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from psycopg.rows import dict_row
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError
from user_agents import parse
import psycopg
import requests
import threading
import random
import re
import os
import hmac
import hashlib
import ipaddress
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

load_dotenv()

app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

app.secret_key = os.getenv("SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing.")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing.")


# ============================================================
# SESSION SETTINGS
# ============================================================

SESSION_TIMEOUT_MINUTES = 60
SESSION_COOKIE_GRACE_MINUTES = 4320

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "False") == "True",
    PERMANENT_SESSION_LIFETIME=timedelta(
        minutes=SESSION_TIMEOUT_MINUTES + SESSION_COOKIE_GRACE_MINUTES
    ),
    SESSION_REFRESH_EACH_REQUEST=False
)

csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
)


# ============================================================
# ENVIRONMENT SETTINGS
# ============================================================

CAMERA_IP = os.getenv("CAMERA_IP", "192.168.1.10")

CAMERA_STREAM_URL = os.getenv(
    "CAMERA_STREAM_URL",
    f"http://{CAMERA_IP}:8080/video"
).strip()

camera_base_url = CAMERA_STREAM_URL.rstrip("/")

if camera_base_url.endswith("/video"):
    camera_base_url = camera_base_url[:-6]

CAMERA_STATUS_URL = os.getenv(
    "CAMERA_STATUS_URL",
    f"{camera_base_url}/shot.jpg"
).strip()

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_WINDOW_MINUTES = 5
IP_BLOCK_MINUTES = 5
ACCOUNT_LOCK_MINUTES = 5
MAX_PASSWORD_LENGTH = 128

USERNAME_PATTERN = re.compile(r"^[a-z0-9_]{3,30}$")

DEVICES = [
    {
        "name": "CCTV Camera",
        "device_type": "cctv_camera",
        "address": CAMERA_STREAM_URL,
        "display_address": "Hidden",
        "status_url": CAMERA_STATUS_URL,
    },
]

PH_TZ = ZoneInfo("Asia/Manila")


# ============================================================
# TIME / SESSION HELPERS
# ============================================================

def get_ph_time():
    return datetime.now(PH_TZ).strftime("%Y-%m-%d %H:%M:%S")


def get_utc_now():
    return datetime.now(timezone.utc)


def get_session_expires_at():
    expires_at = session.get("expires_at")

    if not expires_at:
        return None

    try:
        parsed_expires_at = datetime.fromisoformat(expires_at)

        if parsed_expires_at.tzinfo is None:
            parsed_expires_at = parsed_expires_at.replace(tzinfo=timezone.utc)

        return parsed_expires_at

    except ValueError:
        return None


def get_session_seconds_remaining():
    expires_at = get_session_expires_at()

    if not expires_at:
        return 0

    seconds_remaining = int((expires_at - get_utc_now()).total_seconds())
    return max(0, seconds_remaining)


def is_current_session_expired():
    return "user_id" in session and get_session_seconds_remaining() <= 0


def get_session_timeout_event_text():
    expires_at = get_session_expires_at()

    if not expires_at:
        return "Session Timeout"

    expired_at_ph = expires_at.astimezone(PH_TZ).strftime("%Y-%m-%d %H:%M:%S")

    return f"Session Timeout - expired at {expired_at_ph}"


def log_current_session_timeout_once():
    username = session.get("username", "UNKNOWN")
    timeout_event = get_session_timeout_event_text()
    ip_address = get_client_ip()

    if not was_recent_log_logged(username, ip_address, timeout_event, seconds=60):
        add_log(timeout_event, username)


def refresh_current_session_timeout():
    session["expires_at"] = (
        get_utc_now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
    ).isoformat()
    session.modified = True


def get_password_version(password):
    if not password:
        return None

    secret = app.secret_key.encode("utf-8")
    password_bytes = password.encode("utf-8")

    return hmac.new(secret, password_bytes, hashlib.sha256).hexdigest()


def get_current_user_password_version(user_id):
    if not user_id:
        return None

    with get_db_connection() as conn:
        user = conn.execute(
            "SELECT password_version FROM users WHERE id = %s",
            (user_id,)
        ).fetchone()

    if not user:
        return None

    return user.get("password_version")


def is_logged_in_password_version_current():
    user_id = session.get("user_id")
    session_password_version = session.get("password_version")

    if not user_id or not session_password_version:
        return False

    current_password_version = get_current_user_password_version(user_id)

    if not current_password_version:
        return False

    return hmac.compare_digest(
        str(session_password_version),
        str(current_password_version)
    )


# ============================================================
# CAPTCHA HELPERS
# ============================================================

def get_captcha_serializer():
    return URLSafeTimedSerializer(app.secret_key, salt="login-captcha")


def generate_login_captcha():
    number_one = random.randint(2, 9)
    number_two = random.randint(2, 9)
    answer = str(number_one + number_two)

    captcha_token = get_captcha_serializer().dumps({
        "answer": answer
    })

    return f"{number_one} + {number_two}", captcha_token


def verify_login_captcha(submitted_answer, captcha_token):
    if not submitted_answer or not captcha_token:
        return False

    try:
        data = get_captcha_serializer().loads(
            captcha_token,
            max_age=300
        )

        expected_answer = str(data.get("answer", "")).strip()

        return submitted_answer.strip() == expected_answer

    except (BadSignature, SignatureExpired):
        return False


def render_login_page(status_code=200):
    captcha_question, captcha_token = generate_login_captcha()

    return render_template(
        "login.html",
        captcha_question=captcha_question,
        captcha_token=captcha_token
    ), status_code


# ============================================================
# LOG / SECURITY HELPERS
# ============================================================

def clean_log_value(value, fallback="UNKNOWN", max_length=50):
    if value is None:
        return fallback

    cleaned = str(value).replace("\n", " ").replace("\r", " ").strip()

    if not cleaned:
        return fallback

    return cleaned[:max_length]


def is_valid_username(username):
    return bool(USERNAME_PATTERN.fullmatch(username))


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For")

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "UNKNOWN"


def get_device_info():
    client_device_info = request.form.get("client_device_info", "").strip()

    if client_device_info:
        return clean_log_value(client_device_info, "Unknown device", 150)

    saved_device_info = session.get("device_info")

    if saved_device_info:
        return clean_log_value(saved_device_info, "Unknown device", 150)

    user_agent_string = request.headers.get("User-Agent", "")

    if not user_agent_string:
        return "Unknown device"

    lowered_user_agent = user_agent_string.lower()

    script_tools = [
        "curl",
        "python-requests",
        "httpie",
        "postman",
        "wget",
        "go-http-client"
    ]

    if any(tool in lowered_user_agent for tool in script_tools):
        return "Unknown script/tool"

    user_agent = parse(user_agent_string)
    operating_system = user_agent.os.family or "Unknown OS"

    is_ipad_disguised_as_mac = (
        "macintosh" in lowered_user_agent
        and "mobile" in lowered_user_agent
        and "safari" in lowered_user_agent
    )

    if "ipad" in lowered_user_agent or is_ipad_disguised_as_mac:
        operating_system = "iPadOS"
        device_type = "Tablet"
    elif user_agent.is_mobile:
        device_type = "Mobile"
    elif user_agent.is_tablet:
        device_type = "Tablet"
    elif user_agent.is_pc:
        device_type = "Desktop"
    elif user_agent.is_bot:
        device_type = "Bot"
    else:
        device_type = "Unknown Device"

    return f"{operating_system} ({device_type})"


def get_db_connection():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def post_discord_alert_async(message):
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=2)
    except requests.RequestException:
        pass


def send_discord_alert(event, username, ip_address, device_info, timestamp):
    if not DISCORD_WEBHOOK_URL:
        return

    safe_event = clean_log_value(event, "UNKNOWN_EVENT", 100)
    safe_username = clean_log_value(username, "UNKNOWN", 50)
    safe_ip = clean_log_value(ip_address, "UNKNOWN_IP", 100)
    safe_device = clean_log_value(device_info, "UNKNOWN_DEVICE", 150)

    message = {
        "content": (
            "**Security Alert**\n"
            f"Event: `{safe_event}`\n"
            f"User: `{safe_username}`\n"
            f"IP Address: `{safe_ip}`\n"
            f"Device: `{safe_device}`\n"
            f"Time: `{timestamp}`"
        ),
        "allowed_mentions": {
            "parse": []
        }
    }

    threading.Thread(
        target=post_discord_alert_async,
        args=(message,),
        daemon=True
    ).start()


def add_log(event, username):
    timestamp = get_ph_time()
    ip_address = get_client_ip()
    device_info = get_device_info()

    safe_event = clean_log_value(event, "UNKNOWN_EVENT", 100)
    safe_username = clean_log_value(username, "UNKNOWN", 50)

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO system_logs (time, event, username, ip_address, browser_info)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (timestamp, safe_event, safe_username, ip_address, device_info)
        )

    send_discord_alert(safe_event, safe_username, ip_address, device_info, timestamp)


def was_recent_log_logged(username, ip_address, event, seconds=60):
    safe_username = clean_log_value(username, "UNKNOWN", 50)
    safe_ip = clean_log_value(ip_address, "UNKNOWN_IP", 100)
    safe_event = clean_log_value(event, "UNKNOWN_EVENT", 100)

    with get_db_connection() as conn:
        recent_logs = conn.execute(
            """
            SELECT time
            FROM system_logs
            WHERE username = %s
              AND ip_address = %s
              AND event = %s
            ORDER BY id DESC
            LIMIT 5
            """,
            (safe_username, safe_ip, safe_event)
        ).fetchall()

    now_ph = datetime.now(PH_TZ)

    for log in recent_logs:
        try:
            logged_time = datetime.strptime(log["time"], "%Y-%m-%d %H:%M:%S")
            logged_time = logged_time.replace(tzinfo=PH_TZ)

            if (now_ph - logged_time).total_seconds() <= seconds:
                return True

        except (ValueError, TypeError):
            continue

    return False


# ============================================================
# CAMERA / DEVICE STATUS HELPERS
# ============================================================

def get_camera_request_headers():
    return {
        "ngrok-skip-browser-warning": "true",
        "User-Agent": "Mozilla/5.0",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache"
    }


def add_cache_buster(url):
    parts = urlsplit(url)
    query_items = parse_qsl(parts.query, keep_blank_values=True)
    query_items.append(("t", str(int(get_utc_now().timestamp() * 1000))))

    return urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        urlencode(query_items),
        parts.fragment
    ))


def is_camera_stream_online(status_url, timeout=1.5):
    if not status_url:
        return False

    try:
        status_request_url = add_cache_buster(status_url)

        with requests.get(
            status_request_url,
            headers=get_camera_request_headers(),
            timeout=timeout
        ) as response:
            content_type = response.headers.get("Content-Type", "").lower()

            if response.status_code >= 400:
                return False

            if "text/html" in content_type:
                return False

            return True

    except requests.RequestException:
        return False


def get_device_statuses():
    device_statuses = []

    for device in DEVICES:
        online = is_camera_stream_online(device["status_url"])

        device_statuses.append({
            "name": device["name"],
            "device_type": device.get("device_type", "device"),
            "ip": device.get("display_address", "Hidden"),
            "status": "Online" if online else "Offline / Not Detected",
            "online": online
        })

    return device_statuses


def get_initial_device_statuses():
    initial_devices = []

    for device in DEVICES:
        initial_devices.append({
            "name": device["name"],
            "device_type": device.get("device_type", "device"),
            "ip": device.get("display_address", "Hidden"),
            "status": "Checking...",
            "online": False
        })

    return initial_devices


# ============================================================
# LOGIN PROTECTION HELPERS
# ============================================================

def is_ip_blocked(ip_address):
    now = get_utc_now()

    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM blocked_ips WHERE blocked_until <= %s",
            (now,)
        )

        blocked_ip = conn.execute(
            """
            SELECT blocked_until
            FROM blocked_ips
            WHERE ip_address = %s AND blocked_until > %s
            """,
            (ip_address, now)
        ).fetchone()

    return blocked_ip is not None


def normalize_ip_address(ip_address):
    raw_ip = clean_log_value(ip_address, "", 100)

    if not raw_ip:
        return None

    try:
        return str(ipaddress.ip_address(raw_ip))
    except ValueError:
        return None


def is_carlson_admin():
    return session.get("username") == "carlson"


def normalize_username_value(username):
    safe_username = clean_log_value(username, "", 50).lower()

    if not safe_username or not is_valid_username(safe_username):
        return None

    return safe_username


def is_user_manually_blocked(username):
    safe_username = normalize_username_value(username)

    if not safe_username:
        return False

    now = get_utc_now()

    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM blocked_users WHERE blocked_until <= %s",
            (now,)
        )

        blocked_user = conn.execute(
            """
            SELECT blocked_until
            FROM blocked_users
            WHERE username = %s AND blocked_until > %s
            """,
            (safe_username, now)
        ).fetchone()

    return blocked_user is not None


def user_exists(username):
    safe_username = normalize_username_value(username)

    if not safe_username:
        return False

    with get_db_connection() as conn:
        user = conn.execute(
            "SELECT id FROM users WHERE username = %s",
            (safe_username,)
        ).fetchone()

    return user is not None


def format_blocked_until(blocked_until):
    if not blocked_until:
        return "N/A"

    try:
        if blocked_until.tzinfo is None:
            blocked_until = blocked_until.replace(tzinfo=timezone.utc)

        return blocked_until.astimezone(PH_TZ).strftime("%Y-%m-%d %H:%M:%S")
    except AttributeError:
        return str(blocked_until)


def is_username_locked(username):
    now = get_utc_now()
    safe_username = clean_log_value(username, "UNKNOWN", 50)

    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM locked_accounts WHERE locked_until <= %s",
            (now,)
        )

        locked_username = conn.execute(
            """
            SELECT locked_until
            FROM locked_accounts
            WHERE username = %s AND locked_until > %s
            """,
            (safe_username, now)
        ).fetchone()

    return locked_username is not None


def record_failed_attempt(username, ip_address):
    now = get_utc_now()
    window_start = now - timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)
    ip_blocked_until = now + timedelta(minutes=IP_BLOCK_MINUTES)
    username_locked_until = now + timedelta(minutes=ACCOUNT_LOCK_MINUTES)

    safe_username = clean_log_value(username, "invalid_username", 50)

    result = {
        "ip_blocked": False,
        "username_locked": False
    }

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO failed_login_attempts (ip_address, username, attempted_at)
            VALUES (%s, %s, %s)
            """,
            (ip_address, safe_username, now)
        )

        conn.execute(
            """
            DELETE FROM failed_login_attempts
            WHERE attempted_at < %s
            """,
            (now - timedelta(hours=24),)
        )

        failed_ip_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM failed_login_attempts
            WHERE ip_address = %s AND attempted_at >= %s
            """,
            (ip_address, window_start)
        ).fetchone()["count"]

        failed_username_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM failed_login_attempts
            WHERE username = %s AND attempted_at >= %s
            """,
            (safe_username, window_start)
        ).fetchone()["count"]

        if failed_ip_count >= FAILED_LOGIN_LIMIT:
            conn.execute(
                """
                INSERT INTO blocked_ips (ip_address, blocked_until, reason)
                VALUES (%s, %s, %s)
                ON CONFLICT (ip_address)
                DO UPDATE SET
                    blocked_until = EXCLUDED.blocked_until,
                    reason = EXCLUDED.reason
                """,
                (
                    ip_address,
                    ip_blocked_until,
                    "Too many failed login attempts from this IP"
                )
            )

            result["ip_blocked"] = True

        if safe_username not in ["UNKNOWN", "invalid_username"] and failed_username_count >= FAILED_LOGIN_LIMIT:
            conn.execute(
                """
                INSERT INTO locked_accounts (username, locked_until, reason)
                VALUES (%s, %s, %s)
                ON CONFLICT (username)
                DO UPDATE SET
                    locked_until = EXCLUDED.locked_until,
                    reason = EXCLUDED.reason
                """,
                (
                    safe_username,
                    username_locked_until,
                    "Too many failed login attempts for this username"
                )
            )

            result["username_locked"] = True

    return result


def clear_failed_attempts(ip_address, username):
    safe_username = clean_log_value(username, "UNKNOWN", 50)

    with get_db_connection() as conn:
        conn.execute(
            """
            DELETE FROM failed_login_attempts
            WHERE ip_address = %s OR username = %s
            """,
            (ip_address, safe_username)
        )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
        """)

        conn.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS password_version TEXT;
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS system_logs (
                id SERIAL PRIMARY KEY,
                time VARCHAR(50) NOT NULL,
                event VARCHAR(100) NOT NULL,
                username VARCHAR(50) NOT NULL,
                ip_address VARCHAR(100),
                browser_info VARCHAR(150)
            );
        """)

        conn.execute("""
            ALTER TABLE system_logs
            ADD COLUMN IF NOT EXISTS ip_address VARCHAR(100);
        """)

        conn.execute("""
            ALTER TABLE system_logs
            ADD COLUMN IF NOT EXISTS browser_info VARCHAR(150);
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS failed_login_attempts (
                id SERIAL PRIMARY KEY,
                ip_address VARCHAR(100) NOT NULL,
                username VARCHAR(50) NOT NULL,
                attempted_at TIMESTAMPTZ NOT NULL
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address VARCHAR(100) PRIMARY KEY,
                blocked_until TIMESTAMPTZ NOT NULL,
                reason TEXT
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS locked_accounts (
                username VARCHAR(50) PRIMARY KEY,
                locked_until TIMESTAMPTZ NOT NULL,
                reason TEXT
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_users (
                username VARCHAR(50) PRIMARY KEY,
                blocked_until TIMESTAMPTZ NOT NULL,
                reason TEXT
            );
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_failed_login_attempts_ip_time
            ON failed_login_attempts (ip_address, attempted_at);
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_failed_login_attempts_username_time
            ON failed_login_attempts (username, attempted_at);
        """)

        default_users = [
            ("carlson", os.getenv("CARLSON_PASSWORD")),
            ("rafael", os.getenv("RAFAEL_PASSWORD")),
            ("steven", os.getenv("STEVEN_PASSWORD")),
            ("patrick", os.getenv("PATRICK_PASSWORD")),
            ("sirnetad", os.getenv("SIRNETAD_PASSWORD")),
        ]

        for username, password in default_users:
            if not password:
                continue

            password_hash = generate_password_hash(password)
            password_version = get_password_version(password)

            conn.execute(
                """
                INSERT INTO users (username, password_hash, password_version)
                VALUES (%s, %s, %s)
                ON CONFLICT (username)
                DO UPDATE SET
                    password_hash = EXCLUDED.password_hash,
                    password_version = EXCLUDED.password_version;
                """,
                (username, password_hash, password_version)
            )


# ============================================================
# SECURITY HEADERS / ERRORS / SESSION ENFORCEMENT
# ============================================================

@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' http: https: data:; "
        "media-src 'self' blob:; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )

    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


@app.errorhandler(429)
def too_many_requests(error):
    flash(f"Too many failed login attempts. Try again after {IP_BLOCK_MINUTES} minutes.")
    return render_login_page(429)


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    session.clear()
    flash("Security token expired or invalid. Please try again.")
    return redirect(url_for("login"))


@app.before_request
def enforce_session_timeout():
    if request.endpoint == "static":
        return None

    # This endpoint manually checks the idle timer so the dashboard can
    # record an idle timeout before redirecting the user to the login page.
    if request.endpoint == "api_expire_idle_session":
        return None

    if is_current_session_expired():
        log_current_session_timeout_once()
        session.clear()

        if request.path.startswith("/api/") or request.endpoint == "camera_feed":
            return jsonify({
                "authenticated": False,
                "error": "Session expired"
            }), 401

        if request.endpoint == "login":
            return None

        flash("Your session timed out. Please log in again.")
        return redirect(url_for("login"))

    open_endpoints = ["login"]

    if request.endpoint in open_endpoints:
        return None

    if "user_id" not in session:
        if request.path.startswith("/api/") or request.endpoint == "camera_feed":
            return jsonify({
                "authenticated": False,
                "error": "Unauthorized"
            }), 401

        return redirect(url_for("login"))

    if is_ip_blocked(get_client_ip()):
        username = session.get("username", "UNKNOWN")
        ip_address = get_client_ip()
        event = "Forced Logout"

        if not was_recent_log_logged(username, ip_address, event, seconds=30):
            add_log(event, username)

        session.clear()

        if request.path.startswith("/api/") or request.endpoint == "camera_feed":
            return jsonify({
                "authenticated": False,
                "error": "Unauthorized"
            }), 401

        flash("Invalid credentials. Please try again.")
        return redirect(url_for("login"))

    if is_user_manually_blocked(session.get("username")):
        username = session.get("username", "UNKNOWN")
        ip_address = get_client_ip()
        event = "Forced Logout"

        if not was_recent_log_logged(username, ip_address, event, seconds=30):
            add_log(event, username)

        session.clear()

        if request.path.startswith("/api/") or request.endpoint == "camera_feed":
            return jsonify({
                "authenticated": False,
                "error": "Unauthorized"
            }), 401

        flash("Invalid credentials. Please try again.")
        return redirect(url_for("login"))

    if not is_logged_in_password_version_current():
        username = session.get("username", "UNKNOWN")
        ip_address = get_client_ip()
        event = "Forced Logout"

        if not was_recent_log_logged(username, ip_address, event, seconds=30):
            add_log(event, username)

        session.clear()

        if request.path.startswith("/api/") or request.endpoint == "camera_feed":
            return jsonify({
                "authenticated": False,
                "error": "Session revoked. Please log in again."
            }), 401

        flash("Your session was revoked. Please log in again.")
        return redirect(url_for("login"))

    return None


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        submitted_captcha = request.form.get("captcha_answer", "").strip()
        captcha_token = request.form.get("captcha_token", "").strip()

        ip_address = get_client_ip()
        detected_device_info = get_device_info()

        if is_ip_blocked(ip_address):
            add_log("Blocked Login Attempt", username or "UNKNOWN")
            flash("Invalid credentials. Please try again.")
            return render_login_page()

        if not verify_login_captcha(submitted_captcha, captcha_token):
            add_log("Failed CAPTCHA Attempt", username or "UNKNOWN")

            if is_valid_username(username):
                failed_attempt_username = username
            else:
                failed_attempt_username = "invalid_username"

            block_result = record_failed_attempt(failed_attempt_username, ip_address)

            if block_result["ip_blocked"]:
                add_log("IP Temporarily Blocked", failed_attempt_username)
                flash(f"Too many failed login attempts. Try again after {IP_BLOCK_MINUTES} minutes.")
                return render_login_page(429)

            if block_result["username_locked"]:
                add_log("Username Temporarily Locked", failed_attempt_username)
                flash(f"Too many failed login attempts. Try again after {ACCOUNT_LOCK_MINUTES} minutes.")
                return render_login_page(429)

            flash("Incorrect security check. Please try again.")
            return render_login_page()

        if not is_valid_username(username):
            add_log("Invalid Username Format", username or "EMPTY")

            block_result = record_failed_attempt("invalid_username", ip_address)

            if block_result["ip_blocked"]:
                add_log("IP Temporarily Blocked", "invalid_username")
                flash(f"Too many failed login attempts. Try again after {IP_BLOCK_MINUTES} minutes.")
                return render_login_page(429)

            flash("Invalid credentials. Please try again.")
            return render_login_page()

        if is_user_manually_blocked(username):
            add_log("Blocked Login Attempt", username)
            flash("Invalid credentials. Please try again.")
            return render_login_page()

        if is_username_locked(username):
            add_log("Blocked Login Attempt", username)
            flash(f"Too many failed login attempts. Try again after {ACCOUNT_LOCK_MINUTES} minutes.")
            return render_login_page(429)

        if len(password) < 1 or len(password) > MAX_PASSWORD_LENGTH:
            add_log("Failed Login Attempt", username)

            block_result = record_failed_attempt(username, ip_address)

            if block_result["ip_blocked"]:
                add_log("IP Temporarily Blocked", username)
                flash(f"Too many failed login attempts. Try again after {IP_BLOCK_MINUTES} minutes.")
                return render_login_page(429)

            if block_result["username_locked"]:
                add_log("Username Temporarily Locked", username)
                flash(f"Too many failed login attempts. Try again after {ACCOUNT_LOCK_MINUTES} minutes.")
                return render_login_page(429)

            flash("Invalid credentials. Please try again.")
            return render_login_page()

        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT id, username, password_hash, password_version FROM users WHERE username = %s",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = True

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["device_info"] = detected_device_info
            session["password_version"] = user["password_version"]

            session["expires_at"] = (
                get_utc_now() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
            ).isoformat()

            clear_failed_attempts(ip_address, username)
            add_log("Successful Login", username)

            return redirect(url_for("dashboard"))

        flash("Invalid credentials. Please try again.")
        add_log("Failed Login Attempt", username)

        block_result = record_failed_attempt(username, ip_address)

        if block_result["ip_blocked"]:
            add_log("IP Temporarily Blocked", username)
            flash(f"Too many failed login attempts. Try again after {IP_BLOCK_MINUTES} minutes.")
            return render_login_page(429)

        if block_result["username_locked"]:
            add_log("Username Temporarily Locked", username)
            flash(f"Too many failed login attempts. Try again after {ACCOUNT_LOCK_MINUTES} minutes.")
            return render_login_page(429)

    return render_login_page()


@app.route("/logout", methods=["POST"])
def logout():
    username = session.get("username", "UNKNOWN")
    ip_address = get_client_ip()

    if "user_id" in session:
        if not was_recent_log_logged(username, ip_address, "Logout", seconds=10):
            add_log("Logout", username)

    session.clear()

    return redirect(url_for("login"))


@app.route("/api/session-status")
@limiter.exempt
def api_session_status():
    if "user_id" not in session:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized"
        }), 401

    return jsonify({
        "authenticated": True,
        "seconds_remaining": get_session_seconds_remaining()
    })


@app.route("/api/expire-idle-session", methods=["POST"])
@limiter.exempt
def api_expire_idle_session():
    if "user_id" not in session:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized"
        }), 401

    seconds_remaining = get_session_seconds_remaining()

    if seconds_remaining > 0:
        return jsonify({
            "authenticated": True,
            "expired": False,
            "seconds_remaining": seconds_remaining
        })

    log_current_session_timeout_once()
    session.clear()

    return jsonify({
        "authenticated": False,
        "expired": True,
        "error": "Session expired"
    }), 401


@app.route("/api/keep-session-alive", methods=["POST"])
@limiter.exempt
def api_keep_session_alive():
    if "user_id" not in session:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized"
        }), 401

    refresh_current_session_timeout()

    return jsonify({
        "authenticated": True,
        "seconds_remaining": get_session_seconds_remaining()
    })


@app.route("/api/logs")
@limiter.exempt
def api_logs():
    if "user_id" not in session:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized"
        }), 401

    try:
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        limit = 50
        offset = 0

    limit = max(1, min(limit, 100))
    offset = max(0, offset)

    jump_to_oldest = request.args.get("oldest", "false").lower() == "true"

    with get_db_connection() as conn:
        total_count = conn.execute(
            "SELECT COUNT(*) AS count FROM system_logs"
        ).fetchone()["count"]

        if jump_to_oldest:
            offset = max(total_count - limit, 0)

        logs = conn.execute(
            """
            SELECT time, username AS user, event, ip_address, browser_info
            FROM system_logs
            ORDER BY id DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset)
        ).fetchall()

    return jsonify({
        "logs": [dict(log) for log in logs],
        "limit": limit,
        "offset": offset,
        "total_count": total_count,
        "has_newer": offset > 0,
        "has_older": offset + limit < total_count
    })


@app.route("/api/devices")
@limiter.exempt
def api_devices():
    if "user_id" not in session:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized"
        }), 401

    return jsonify({
        "devices": get_device_statuses()
    })


@app.route("/api/blocked-ips")
@limiter.exempt
def api_blocked_ips():
    if "user_id" not in session:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized"
        }), 401

    if not is_carlson_admin():
        return jsonify({
            "authenticated": False,
            "error": "Forbidden"
        }), 403

    now = get_utc_now()

    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM blocked_ips WHERE blocked_until <= %s",
            (now,)
        )

        blocked_ips = conn.execute(
            """
            SELECT ip_address, blocked_until, reason
            FROM blocked_ips
            WHERE blocked_until > %s
            ORDER BY blocked_until DESC
            LIMIT 25
            """,
            (now,)
        ).fetchall()

    return jsonify({
        "blocked_ips": [
            {
                "ip_address": row["ip_address"],
                "blocked_until": format_blocked_until(row["blocked_until"]),
                "reason": row.get("reason") or "Manual block"
            }
            for row in blocked_ips
        ]
    })


@app.route("/api/block-ip", methods=["POST"])
@limiter.exempt
def api_block_ip():
    if "user_id" not in session:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized"
        }), 401

    if not is_carlson_admin():
        return jsonify({
            "authenticated": False,
            "error": "Forbidden"
        }), 403

    data = request.get_json(silent=True) or {}

    ip_address = normalize_ip_address(data.get("ip_address", ""))

    if not ip_address:
        return jsonify({
            "success": False,
            "error": "Enter a valid IPv4 or IPv6 address."
        }), 400

    if ip_address == normalize_ip_address(get_client_ip()):
        return jsonify({
            "success": False,
            "error": "You cannot block your own current IP address from this panel."
        }), 400

    try:
        duration_minutes = int(data.get("duration_minutes", 60))
    except (TypeError, ValueError):
        duration_minutes = 60

    duration_minutes = max(1, min(duration_minutes, 10080))
    blocked_until = get_utc_now() + timedelta(minutes=duration_minutes)
    reason = clean_log_value(
        data.get("reason") or f"Manual block by {session.get('username', 'carlson')}",
        "Manual block",
        150
    )

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO blocked_ips (ip_address, blocked_until, reason)
            VALUES (%s, %s, %s)
            ON CONFLICT (ip_address)
            DO UPDATE SET
                blocked_until = EXCLUDED.blocked_until,
                reason = EXCLUDED.reason
            """,
            (ip_address, blocked_until, reason)
        )


    return jsonify({
        "success": True,
        "ip_address": ip_address,
        "blocked_until": format_blocked_until(blocked_until)
    })


@app.route("/api/unblock-ip", methods=["POST"])
@limiter.exempt
def api_unblock_ip():
    if "user_id" not in session:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized"
        }), 401

    if not is_carlson_admin():
        return jsonify({
            "authenticated": False,
            "error": "Forbidden"
        }), 403

    data = request.get_json(silent=True) or {}
    ip_address = normalize_ip_address(data.get("ip_address", ""))

    if not ip_address:
        return jsonify({
            "success": False,
            "error": "Enter a valid IPv4 or IPv6 address."
        }), 400

    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM blocked_ips WHERE ip_address = %s",
            (ip_address,)
        )


    return jsonify({
        "success": True,
        "ip_address": ip_address
    })


@app.route("/api/blocked-users")
@limiter.exempt
def api_blocked_users():
    if "user_id" not in session:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized"
        }), 401

    if not is_carlson_admin():
        return jsonify({
            "authenticated": False,
            "error": "Forbidden"
        }), 403

    now = get_utc_now()

    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM blocked_users WHERE blocked_until <= %s",
            (now,)
        )

        blocked_users = conn.execute(
            """
            SELECT username, blocked_until, reason
            FROM blocked_users
            WHERE blocked_until > %s
            ORDER BY blocked_until DESC
            LIMIT 25
            """,
            (now,)
        ).fetchall()

    return jsonify({
        "blocked_users": [
            {
                "username": row["username"],
                "blocked_until": format_blocked_until(row["blocked_until"]),
                "reason": row.get("reason") or "Manual user block"
            }
            for row in blocked_users
        ]
    })


@app.route("/api/block-user", methods=["POST"])
@limiter.exempt
def api_block_user():
    if "user_id" not in session:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized"
        }), 401

    if not is_carlson_admin():
        return jsonify({
            "authenticated": False,
            "error": "Forbidden"
        }), 403

    data = request.get_json(silent=True) or {}
    username = normalize_username_value(data.get("username", ""))

    if not username:
        return jsonify({
            "success": False,
            "error": "Enter a valid username."
        }), 400

    if username == "carlson":
        return jsonify({
            "success": False,
            "error": "You cannot block carlson from this panel."
        }), 400

    if not user_exists(username):
        return jsonify({
            "success": False,
            "error": "Username does not exist in the system."
        }), 404

    try:
        duration_minutes = int(data.get("duration_minutes", 60))
    except (TypeError, ValueError):
        duration_minutes = 60

    duration_minutes = max(1, min(duration_minutes, 10080))
    blocked_until = get_utc_now() + timedelta(minutes=duration_minutes)
    reason = clean_log_value(
        data.get("reason") or f"Manual user block by {session.get('username', 'carlson')}",
        "Manual user block",
        150
    )

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO blocked_users (username, blocked_until, reason)
            VALUES (%s, %s, %s)
            ON CONFLICT (username)
            DO UPDATE SET
                blocked_until = EXCLUDED.blocked_until,
                reason = EXCLUDED.reason
            """,
            (username, blocked_until, reason)
        )

    return jsonify({
        "success": True,
        "username": username,
        "blocked_until": format_blocked_until(blocked_until)
    })


@app.route("/api/unblock-user", methods=["POST"])
@limiter.exempt
def api_unblock_user():
    if "user_id" not in session:
        return jsonify({
            "authenticated": False,
            "error": "Unauthorized"
        }), 401

    if not is_carlson_admin():
        return jsonify({
            "authenticated": False,
            "error": "Forbidden"
        }), 403

    data = request.get_json(silent=True) or {}
    username = normalize_username_value(data.get("username", ""))

    if not username:
        return jsonify({
            "success": False,
            "error": "Enter a valid username."
        }), 400

    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM blocked_users WHERE username = %s",
            (username,)
        )

    return jsonify({
        "success": True,
        "username": username
    })


@app.route("/camera-feed")
@limiter.exempt
def camera_feed():
    if "user_id" not in session:
        return "Unauthorized", 401

    try:
        upstream_response = requests.get(
            CAMERA_STREAM_URL,
            headers=get_camera_request_headers(),
            stream=True,
            timeout=(5, 30)
        )

        if upstream_response.status_code >= 400:
            upstream_response.close()
            return "Camera feed unavailable", 502

        content_type = upstream_response.headers.get(
            "Content-Type",
            "multipart/x-mixed-replace"
        )

        def generate_camera_stream():
            try:
                for chunk in upstream_response.iter_content(chunk_size=8192):
                    if chunk:
                        yield chunk
            finally:
                upstream_response.close()

        return Response(
            stream_with_context(generate_camera_stream()),
            content_type=content_type,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )

    except requests.RequestException:
        return "Camera feed unavailable", 502


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        logs = conn.execute(
            """
            SELECT time, username AS user, event, ip_address, browser_info
            FROM system_logs
            ORDER BY id DESC
            LIMIT 50
            """
        ).fetchall()

    return render_template(
        "dashboard.html",
        logs=logs,
        devices=get_initial_device_statuses(),
        camera_stream_url=CAMERA_STREAM_URL,
        session_seconds_remaining=get_session_seconds_remaining(),
        is_carlson_admin=is_carlson_admin(),
        current_ip=get_client_ip()
    )


initialize_database()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("FLASK_DEBUG", "False") == "True"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)