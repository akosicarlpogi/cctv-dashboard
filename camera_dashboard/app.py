from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime
from zoneinfo import ZoneInfo
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from psycopg.rows import dict_row
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg
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
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "False") == "True"
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

CAMERA_IP = os.getenv("CAMERA_IP", "192.168.1.10")
CAMERA_URL = f"http://{CAMERA_IP}/snapshot.jpg"

PH_TZ = ZoneInfo("Asia/Manila")


def get_ph_time():
    return datetime.now(PH_TZ).strftime("%Y-%m-%d %H:%M:%S")


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For")

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "UNKNOWN"


def get_db_connection():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def add_log(event, username):
    timestamp = get_ph_time()
    ip_address = get_client_ip()

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO system_logs (time, event, username, ip_address)
            VALUES (%s, %s, %s, %s)
            """,
            (timestamp, event, username, ip_address)
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
                ip_address VARCHAR(100)
            );
        """)

        conn.execute("""
            ALTER TABLE system_logs
            ADD COLUMN IF NOT EXISTS ip_address VARCHAR(100);
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


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT id, username, password_hash FROM users WHERE username = %s",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            add_log("Successful Login", username)

            return redirect(url_for("dashboard"))

        flash("Invalid credentials. Please try again.")
        add_log("Failed Login Attempt", username)

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
            SELECT time, username AS user, event, ip_address
            FROM system_logs
            ORDER BY id DESC
            """
        ).fetchall()

    return render_template(
        "dashboard.html",
        camera_url=CAMERA_URL,
        logs=logs
    )


initialize_database()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("FLASK_DEBUG", "False") == "True"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)