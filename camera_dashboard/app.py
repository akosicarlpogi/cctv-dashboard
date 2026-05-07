from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from psycopg.rows import dict_row
import psycopg
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

DATABASE_URL = os.getenv("DATABASE_URL")

CAMERA_IP = os.getenv("CAMERA_IP", "192.168.1.10")
CAMERA_URL = f"http://{CAMERA_IP}/snapshot.jpg"


def get_db_connection():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def add_log(event, username):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO system_logs (time, event, username) VALUES (%s, %s, %s)",
            (timestamp, event, username)
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
                username VARCHAR(50) NOT NULL
            );
        """)

        existing_users = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]

        if existing_users == 0:
            default_users = [
                ("carlson", os.getenv("CARLSON_PASSWORD")),
                ("rafael", os.getenv("RAFAEL_PASSWORD")),
                ("steven", os.getenv("STEVEN_PASSWORD")),
                ("patrick", os.getenv("PATRICK_PASSWORD")),
            ]

            for username, password in default_users:
                password_hash = generate_password_hash(password)

                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                    (username, password_hash)
                )

            conn.execute(
                "INSERT INTO system_logs (time, event, username) VALUES (%s, %s, %s)",
                (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "Database initialized and default users created",
                    "SYSTEM"
                )
            )


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()
        password = request.form["password"]

        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = %s",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            add_log("Successful Login", username)

            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials. Please try again.")
            add_log("Failed Login Attempt", username)

    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username", "UNKNOWN")

    add_log("Logout", username)

    session.clear()

    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_db_connection() as conn:
        logs = conn.execute(
            "SELECT time, username AS user, event FROM system_logs ORDER BY id DESC"
        ).fetchall()

    return render_template(
        "dashboard.html",
        camera_url=CAMERA_URL,
        logs=logs
    )


initialize_database()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)