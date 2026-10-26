#!/usr/bin/env python3
"""
Hardened Flask REST API and STRIDE Defense Architecture
Features salted Bcrypt authentication, parameterized SQLite persistence,
sliding-window rate limiting, constant-time secret verification,
HTTP security headers, and structured security audit logging.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import hmac
import os
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv
from flask import Flask, jsonify, request, Response

from crypto import hash_password, verify_password

load_dotenv()

app = Flask(__name__)

# Enforce reasonable payload body bounds (1 MB limit)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

API_KEY = os.getenv("API_KEY")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")
DATABASE_PATH = os.getenv("DATABASE_PATH", "app.db")

# In-memory sliding window rate limiter tracking (IP -> list of timestamps)
_rate_limit_records: Dict[str, List[float]] = {}
RATE_LIMIT_MAX_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60


def get_db_path() -> str:
    """Returns the currently configured database path or memory connection."""
    return os.getenv("DATABASE_PATH", DATABASE_PATH)


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Establishes an isolated SQLite connection with row factories enabled."""
    target_path = db_path if db_path is not None else get_db_path()
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_db(db_path: Optional[str] = None):
    """Context manager ensuring safe commit, rollback, and connection termination."""
    conn = get_db_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[str] = None) -> None:
    """Creates database schema, tables, and security indexes if they do not exist."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                user_identifier TEXT
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);")


# Initialize schema on application startup
init_db()


def record_audit_log(action: str, status: str, user_identifier: Optional[str] = None) -> None:
    """Records an immutable security audit trail event for repudiation mitigation."""
    client_ip = request.remote_addr or "127.0.0.1"
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_logs (timestamp, client_ip, action, status, user_identifier)
                VALUES (?, ?, ?, ?, ?)
                """,
                (now_iso, client_ip, action, status, user_identifier or "anonymous"),
            )
    except Exception as err:
        # Non-fatal to prevent crashing primary flow if logging encounters disk pressure
        app.logger.warning("Audit logging failed: %s", err)


def is_rate_limited(client_ip: str, limit: int = RATE_LIMIT_MAX_REQUESTS, window: int = RATE_LIMIT_WINDOW_SECONDS) -> bool:
    """Sliding-window in-memory rate limiter per client IP address."""
    if app.config.get("TESTING") and not app.config.get("ENFORCE_RATE_LIMIT_IN_TESTS"):
        return False

    now = time.time()
    timestamps = _rate_limit_records.setdefault(client_ip, [])
    # Discard timestamps outside the current sliding window
    _rate_limit_records[client_ip] = [ts for ts in timestamps if now - ts < window]

    if len(_rate_limit_records[client_ip]) >= limit:
        return True

    _rate_limit_records[client_ip].append(now)
    return False


def validate_username(username: Any) -> Tuple[bool, str]:
    """Validates username syntax, length, and character whitelist."""
    if not isinstance(username, str) or not username.strip():
        return False, "Username is required."
    if len(username) < 3 or len(username) > 64:
        return False, "Username must be between 3 and 64 characters."
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return False, "Username contains invalid characters (allowed: alphanumeric, ., _, -)."
    return True, ""


def validate_password(password: Any) -> Tuple[bool, str]:
    """Validates password length and Bcrypt 72-byte ceiling."""
    if not isinstance(password, str) or not password:
        return False, "Password is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password.encode("utf-8")) > 72:
        return False, "Password exceeds maximum supported length (72 bytes for Bcrypt)."
    return True, ""


@app.after_request
def enforce_security_headers(response: Response) -> Response:
    """Injects hardened HTTP security response headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


@app.errorhandler(400)
def handle_bad_request(e):
    return jsonify({"error": "Bad request"}), 400


@app.errorhandler(404)
def handle_not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def handle_method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(429)
def handle_too_many_requests(e):
    return jsonify({"error": "Rate limit exceeded. Please wait before retrying."}), 429


@app.errorhandler(500)
def handle_internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


@app.route("/register", methods=["POST"])
def register():
    """Secure user registration endpoint with input validation and duplicate handling."""
    client_ip = request.remote_addr or "127.0.0.1"
    if is_rate_limited(client_ip):
        record_audit_log("REGISTER", "RATE_LIMITED", client_ip)
        return jsonify({"error": "Rate limit exceeded. Please wait before retrying."}), 429

    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    is_user_valid, user_err = validate_username(username)
    if not is_user_valid:
        return jsonify({"error": user_err}), 400

    is_pass_valid, pass_err = validate_password(password)
    if not is_pass_valid:
        return jsonify({"error": pass_err}), 400

    try:
        hashed = hash_password(password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed),
            )
        record_audit_log("REGISTER", "SUCCESS", username)
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        record_audit_log("REGISTER", "DUPLICATE_FAILED", username)
        return jsonify({"error": "Username already exists"}), 409
    except Exception:
        record_audit_log("REGISTER", "ERROR", username)
        return jsonify({"error": "Failed to register user"}), 500


@app.route("/login", methods=["POST"])
def login():
    """Secure user authentication endpoint with parameterized query and Bcrypt verification."""
    client_ip = request.remote_addr or "127.0.0.1"
    if is_rate_limited(client_ip):
        record_audit_log("LOGIN", "RATE_LIMITED", client_ip)
        return jsonify({"error": "Rate limit exceeded. Please wait before retrying."}), 429

    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        )
        user = cursor.fetchone()

    if user and verify_password(password, user["password"]):
        record_audit_log("LOGIN", "SUCCESS", username)
        return jsonify({"message": "Login successful"}), 200

    record_audit_log("LOGIN", "FAILED", username)
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/admin", methods=["GET"])
def admin_dashboard():
    """Administrative metrics endpoint guarded by constant-time bearer token verification."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header or not auth_header.startswith("Bearer "):
        record_audit_log("ADMIN_ACCESS", "UNAUTHORIZED", "anonymous")
        return jsonify({"error": "Unauthorized"}), 401

    parts = auth_header.split(" ", 1)
    if len(parts) != 2:
        record_audit_log("ADMIN_ACCESS", "MALFORMED_HEADER", "anonymous")
        return jsonify({"error": "Unauthorized"}), 401

    token = parts[1].strip()
    admin_key = os.getenv("ADMIN_API_KEY") or ADMIN_API_KEY
    if not admin_key:
        record_audit_log("ADMIN_ACCESS", "BLOCKED_NO_KEY", "system")
        return jsonify({"error": "Admin access disabled"}), 503

    # Constant-time comparison defends against timing attacks
    if not hmac.compare_digest(token, admin_key):
        record_audit_log("ADMIN_ACCESS", "FORBIDDEN", token[:8] + "...")
        return jsonify({"error": "Forbidden"}), 403

    record_audit_log("ADMIN_ACCESS", "SUCCESS", "admin")
    return jsonify({
        "data": "Confidential Admin Statistics",
        "system_status": "Healthy",
        "environment": "Production",
    }), 200


@app.route("/admin/audit-logs", methods=["GET"])
def admin_audit_logs():
    """Allows administrators to review system audit logs for repudiation defense."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split(" ", 1)[1].strip()
    admin_key = os.getenv("ADMIN_API_KEY") or ADMIN_API_KEY
    if not admin_key or not hmac.compare_digest(token, admin_key):
        return jsonify({"error": "Forbidden"}), 403

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, client_ip, action, status, user_identifier FROM audit_logs ORDER BY id DESC LIMIT 50")
        logs = [dict(row) for row in cursor.fetchall()]

    return jsonify({"audit_logs": logs}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
