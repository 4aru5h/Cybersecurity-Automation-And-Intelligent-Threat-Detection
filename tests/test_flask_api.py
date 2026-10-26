import os
import sys
import tempfile
from pathlib import Path
import pytest

# Ensure module directory is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "03-flask-secure-api"))

from crypto import hash_password, verify_password
import app as flask_app_module


@pytest.fixture
def client():
    # Create an isolated temporary SQLite database for test execution
    temp_dir = tempfile.mkdtemp()
    test_db = os.path.join(temp_dir, "test_api.db")
    os.environ["DATABASE_PATH"] = test_db
    os.environ["ADMIN_API_KEY"] = "super-secret-admin-token-12345"

    flask_app_module.init_db(test_db)
    flask_app_module.app.config["TESTING"] = True

    with flask_app_module.app.test_client() as client:
        yield client

    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except OSError:
            pass


# -------------------------------------------------------------
# 1. CRYPTO UTILITY TESTS
# -------------------------------------------------------------

def test_crypto_hashing_and_verification():
    password = "CorrectHorseBatteryStaple123!"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    # Hashes must differ due to per-call random salt generation
    assert hash1 != hash2
    assert verify_password(password, hash1) is True
    assert verify_password(password, hash2) is True
    assert verify_password("WrongPassword123!", hash1) is False


def test_crypto_invalid_inputs():
    with pytest.raises(ValueError, match="non-empty string"):
        hash_password("")

    with pytest.raises(ValueError, match="Bcrypt maximum bound"):
        hash_password("A" * 73)

    assert verify_password("", "somehash") is False
    assert verify_password("pass", "") is False
    assert verify_password("pass", "malformed_salt_hash") is False


# -------------------------------------------------------------
# 2. REGISTRATION ENDPOINT TESTS
# -------------------------------------------------------------

def test_register_success(client):
    res = client.post("/register", json={"username": "bob", "password": "SecurePassword123!"})
    assert res.status_code == 201
    data = res.get_json()
    assert "User registered successfully" in data["message"]


def test_register_duplicate_username(client):
    client.post("/register", json={"username": "carol", "password": "SecurePassword123!"})
    # Attempting to register same username again must return 409 Conflict
    res = client.post("/register", json={"username": "carol", "password": "SecurePassword123!"})
    assert res.status_code == 409
    assert "Username already exists" in res.get_json()["error"]


def test_register_missing_fields(client):
    res = client.post("/register", json={"username": "dave"})
    assert res.status_code == 400

    res = client.post("/register", json={"password": "Password123!"})
    assert res.status_code == 400


def test_register_short_password(client):
    res = client.post("/register", json={"username": "shortpass_user", "password": "123"})
    assert res.status_code == 400
    assert "at least 8 characters" in res.get_json()["error"]


def test_register_invalid_username_characters(client):
    res = client.post("/register", json={"username": "user<script>", "password": "Password123!"})
    assert res.status_code == 400
    assert "invalid characters" in res.get_json()["error"]


# -------------------------------------------------------------
# 3. LOGIN ENDPOINT TESTS
# -------------------------------------------------------------

def test_login_success(client):
    client.post("/register", json={"username": "eve", "password": "MyStrongPassword123!"})
    res = client.post("/login", json={"username": "eve", "password": "MyStrongPassword123!"})
    assert res.status_code == 200
    assert "Login successful" in res.get_json()["message"]


def test_login_wrong_password(client):
    client.post("/register", json={"username": "frank", "password": "MyStrongPassword123!"})
    res = client.post("/login", json={"username": "frank", "password": "IncorrectPassword!"})
    assert res.status_code == 401
    assert "Invalid credentials" in res.get_json()["error"]


def test_login_nonexistent_user(client):
    res = client.post("/login", json={"username": "nonexistent_ghost", "password": "SomePassword123!"})
    assert res.status_code == 401


# -------------------------------------------------------------
# 4. ADMIN RBAC & BEARER TOKEN TESTS
# -------------------------------------------------------------

def test_admin_no_token(client):
    res = client.get("/admin")
    assert res.status_code == 401


def test_admin_malformed_token_header(client):
    res = client.get("/admin", headers={"Authorization": "Basic 12345"})
    assert res.status_code == 401


def test_admin_invalid_token(client):
    res = client.get("/admin", headers={"Authorization": "Bearer wrong-admin-key"})
    assert res.status_code == 403


def test_admin_valid_token(client):
    res = client.get("/admin", headers={"Authorization": "Bearer super-secret-admin-token-12345"})
    assert res.status_code == 200
    data = res.get_json()
    assert "Confidential Admin Statistics" in data["data"]


def test_admin_audit_logs(client):
    # Perform actions to generate logs
    client.post("/register", json={"username": "audited_user", "password": "Password123!"})
    client.post("/login", json={"username": "audited_user", "password": "WrongPassword!"})

    res = client.get("/admin/audit-logs", headers={"Authorization": "Bearer super-secret-admin-token-12345"})
    assert res.status_code == 200
    logs = res.get_json()["audit_logs"]
    assert len(logs) >= 2


# -------------------------------------------------------------
# 5. SECURITY HEADERS & RATE LIMITING TESTS
# -------------------------------------------------------------

def test_security_headers_present(client):
    res = client.get("/admin")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("X-XSS-Protection") == "1; mode=block"
    assert "default-src 'none'" in res.headers.get("Content-Security-Policy", "")
    assert "max-age=31536000" in res.headers.get("Strict-Transport-Security", "")


def test_rate_limiting_enforcement(client):
    flask_app_module.app.config["ENFORCE_RATE_LIMIT_IN_TESTS"] = True
    flask_app_module._rate_limit_records.clear()

    # Make requests up to the limit
    for _ in range(flask_app_module.RATE_LIMIT_MAX_REQUESTS):
        res = client.post("/login", json={"username": "user", "password": "wrong"})
        assert res.status_code in (400, 401)

    # The next request must trigger rate limit 429
    rate_limited_res = client.post("/login", json={"username": "user", "password": "wrong"})
    assert rate_limited_res.status_code == 429
    assert "Rate limit exceeded" in rate_limited_res.get_json()["error"]

    # Reset test config
    flask_app_module.app.config["ENFORCE_RATE_LIMIT_IN_TESTS"] = False
    flask_app_module._rate_limit_records.clear()
