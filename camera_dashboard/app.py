from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from psycopg.rows import dict_row
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg
import requests
import socket
import os

load_dotenv()

app = Flask(__name__)

# Helps Flask correctly read proxy headers from Railway
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

app.secret_key = os.getenv("SECRET_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing.")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing.")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "False") == "True",

    # Session expires after 1 hour
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_REFRESH_EACH_REQUEST=False
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

CAMERA_IP = os.getenv("CAMERA_IP", "192.168.1.10")
CAMERA_URL = f"http://{CAMERA_IP}/snapshot.jpg"

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")

# Login protection settings
FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_WINDOW_MINUTES = 5
IP_BLOCK_MINUTES = 5

DEVICES = [
    {
        "name": "Router (Gateway)",
        "ip": os.getenv("ROUTER_IP", "192.168.1.1"),
        "port": int(os.getenv("ROUTER_PORT", 80)),
    },
    {
        "name": "Network Switch",
        "ip": os.getenv("SWITCH_IP", "192.168.1.2"),
        "port": int(os.getenv("SWITCH_PORT", 80)),
    },
    {
        "name": "IP Camera",
        "ip": os.getenv("CAMERA_IP", "192.168.1.10"),
        "port": int(os.getenv("CAMERA_PORT", 80)),
    },
]

PH_TZ = ZoneInfo("Asia/Manila")


def get_ph_time():
    return datetime.now(PH_TZ).strftime("%Y-%m-%d %H:%M:%S")


def get_utc_now():
    return datetime.now(timezone.utc)


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For")

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "UNKNOWN"


def get_device_info():
    user_agent = request.headers.get("User-Agent", "").lower()

    if not user_agent:
        return "Unknown device"

    if any(tool in user_agent for tool in ["curl", "python-requests", "httpie", "postman", "wget"]):
        return "Unknown script/tool"

    if "edg/" in user_agent and "windows" in user_agent:
        return "Microsoft Edge on Windows"

    if "edg/" in user_agent and "android" in user_agent:
        return "Microsoft Edge on Android"

    if "chrome" in user_agent and "windows" in user_agent:
        return "Chrome on Windows"

    if "chrome" in user_agent and "android" in user_agent:
        return "Chrome on Android"

    if "firefox" in user_agent and "windows" in user_agent:
        return "Firefox on Windows"

    if "firefox" in user_agent and "android" in user_agent:
        return "Firefox on Android"

    if "safari" in user_agent and "iphone" in user_agent:
        return "Safari on iPhone"

    if "safari" in user_agent and "ipad" in user_agent:
        return "Safari on iPad"

    if "safari" in user_agent and "macintosh" in user_agent:
        return "Safari on Mac"

    if "android" in user_agent:
        return "Android phone browser"

    if "windows" in user_agent:
        return "Windows browser"

    if "iphone" in user_agent:
        return "iPhone browser"

    if "macintosh" in user_agent:
        return "Mac browser"

    return "Unknown browser/device"


def is_device_online(ip_address, port, timeout=1):
    try:
        with socket.create_connection((ip_address, port), timeout=timeout):
            return True
    except OSError:
        return False


def get_device_statuses():
    device_statuses = []

    for device in DEVICES:
        online = is_device_online(device["ip"], device["port"])

        device_statuses.append({
            "name": device["name"],
            "ip": device["ip"],
            "status": "Online" if online else "Offline / Not Detected",
            "online": online
        })

    return device_statuses


def get_db_connection():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def send_discord_alert(event, username, ip_address, device_info, timestamp):
    if not DISCORD_WEBHOOK_URL:
        return

    message = {
        "content": (
            "**Security Alert**\n"
            f"Event: `{event}`\n"
            f"User: `{username}`\n"
            f"IP Address: `{ip_address}`\n"
            f"Device/Browser: `{device_info}`\n"
            f"Time: `{timestamp}`"
        )
    }

    try:
        requests.post(DISCORD_WEBHOOK_URL, json=message, timeout=5)
    except requests.RequestException:
        pass


def add_log(event, username):
    timestamp = get_ph_time()
    ip_address = get_client_ip()
    device_info = get_device_info()

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO system_logs (time, event, username, ip_address, browser_info)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (timestamp, event, username, ip_address, device_info)
        )

    if event in [
        "Failed Login Attempt",
        "Successful Login",
        "Blocked Login Attempt",
        "IP Temporarily Blocked"
    ]:
        send_discord_alert(event, username, ip_address, device_info, timestamp)


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


def record_failed_attempt(username, ip_address):
    now = get_utc_now()
    window_start = now - timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)
    blocked_until = now + timedelta(minutes=IP_BLOCK_MINUTES)

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO failed_login_attempts (ip_address, username, attempted_at)
            VALUES (%s, %s, %s)
            """,
            (ip_address, username, now)
        )

        conn.execute(
            """
            DELETE FROM failed_login_attempts
            WHERE attempted_at < %s
            """,
            (now - timedelta(hours=24),)
        )

        failed_count = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM failed_login_attempts
            WHERE ip_address = %s AND attempted_at >= %s
            """,
            (ip_address, window_start)
        ).fetchone()["count"]

        if failed_count >= FAILED_LOGIN_LIMIT:
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
                    blocked_until,
                    "Too many failed login attempts"
                )
            )

            return True

    return False


def clear_failed_attempts(ip_address):
    with get_db_connection() as conn:
        conn.execute(
            "DELETE FROM failed_login_attempts WHERE ip_address = %s",
            (ip_address,)
        )


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

        default_users = [
            ("carlson", os.getenv("CARLSON_PASSWORD")),
            ("rafael", os.getenv("RAFAEL_PASSWORD")),
            ("steven", os.getenv("STEVEN_PASSWORD")),
            ("patrick", os.getenv("PATRICK_PASSWORD")),
        ]

        for username, password in default_users:
            if not password:
                continue

            password_hash = generate_password_hash(password)

            conn.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (%s, %s)
                ON CONFLICT (username)
                DO UPDATE SET password_hash = EXCLUDED.password_hash;
                """,
                (username, password_hash)
            )


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.errorhandler(429)
def too_many_requests(error):
    flash(f"Too many failed login attempts. Try again after {IP_BLOCK_MINUTES} minutes.")
    return render_template("login.html"), 429


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("30 per minute", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        ip_address = get_client_ip()

        if is_ip_blocked(ip_address):
            add_log("Blocked Login Attempt", username)
            flash(f"Too many failed login attempts. Try again after {IP_BLOCK_MINUTES} minutes.")
            return render_template("login.html"), 429

        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT id, username, password_hash FROM users WHERE username = %s",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            clear_failed_attempts(ip_address)
            add_log("Successful Login", username)

            return redirect(url_for("dashboard"))

        flash("Invalid credentials. Please try again.")
        add_log("Failed Login Attempt", username)

        was_blocked = record_failed_attempt(username, ip_address)

        if was_blocked:
            add_log("IP Temporarily Blocked", username)
            flash(f"Too many failed login attempts. Try again after {IP_BLOCK_MINUTES} minutes.")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    username = session.get("username", "UNKNOWN")

    if "user_id" in session:
        add_log("Logout", username)

    session.clear()

    return redirect(url_for("login"))


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
            """
        ).fetchall()

    return render_template(
        "dashboard.html",
        camera_url=CAMERA_URL,
        logs=logs,
        devices=get_device_statuses()
    )


initialize_database()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("FLASK_DEBUG", "False") == "True"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)