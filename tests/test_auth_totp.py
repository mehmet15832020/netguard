"""
MFA/TOTP testleri — T2-3

Kapsam:
- setup → confirm → verify tam akışı
- Yanlış kod → 400/401
- Süresi dolmuş mfa_token → 401
- TOTP devre dışıyken normal login → tam token
- TOTP etkinken login → mfa_required=true, mfa_token dolu
- disable → login normal
- get_user_totp tenant izolasyonu
"""

import time
import pyotp
import pytest
import bcrypt
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from server.main import app
from server.auth import (
    create_access_token,
    create_mfa_token,
    MFA_TOKEN_EXPIRE_MINUTES,
)

client = TestClient(app)


# ─── Yardımcı fonksiyonlar ────────────────────────────────────────


def _make_user(tmp_db, username: str = "totp_user", role: str = "viewer") -> dict:
    pw_hash = bcrypt.hashpw(b"testpass123", bcrypt.gensalt()).decode()
    tmp_db.create_db_user(username, pw_hash, role, "default")
    return {"username": username, "password": "testpass123"}


def _auth_header(username: str = "admin", role: str = "admin") -> dict:
    token = create_access_token(username=username, role=role, tenant_id="default")
    return {"Authorization": f"Bearer {token}"}


def _setup_totp(tmp_db, username: str) -> str:
    token = create_access_token(username=username, role="viewer", tenant_id="default")
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/v1/auth/totp-setup", headers=headers)
    assert r.status_code == 200
    secret = r.json()["secret"]
    return secret


def _confirm_totp(username: str, secret: str) -> None:
    code = pyotp.TOTP(secret).now()
    token = create_access_token(username=username, role="viewer", tenant_id="default")
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/v1/auth/totp-confirm", json={"code": code}, headers=headers)
    assert r.status_code == 200


# ─── DB Metod Testleri ────────────────────────────────────────────


class TestTotpDbMethods:
    def test_get_user_totp_nonexistent_user_returns_defaults(self, tmp_db):
        result = tmp_db.get_user_totp("olmayan_kullanici")
        assert result["totp_secret"] is None
        assert result["totp_enabled"] is False

    def test_set_user_totp_secret_stores_secret(self, tmp_db):
        _make_user(tmp_db, "db_secret_user")
        tmp_db.set_user_totp_secret("db_secret_user", "TESTSECRET123456")
        result = tmp_db.get_user_totp("db_secret_user")
        assert result["totp_secret"] == "TESTSECRET123456"
        assert result["totp_enabled"] is False

    def test_enable_user_totp_sets_flag(self, tmp_db):
        _make_user(tmp_db, "db_enable_user")
        tmp_db.set_user_totp_secret("db_enable_user", "ENABLESECRET1234")
        tmp_db.enable_user_totp("db_enable_user")
        result = tmp_db.get_user_totp("db_enable_user")
        assert result["totp_enabled"] is True

    def test_disable_user_totp_clears_secret_and_flag(self, tmp_db):
        _make_user(tmp_db, "db_disable_user")
        tmp_db.set_user_totp_secret("db_disable_user", "DISABLESECRET123")
        tmp_db.enable_user_totp("db_disable_user")
        tmp_db.disable_user_totp("db_disable_user")
        result = tmp_db.get_user_totp("db_disable_user")
        assert result["totp_secret"] is None
        assert result["totp_enabled"] is False

    def test_set_secret_does_not_enable(self, tmp_db):
        _make_user(tmp_db, "db_notenabledyet")
        tmp_db.set_user_totp_secret("db_notenabledyet", "SOMESECRET123456")
        result = tmp_db.get_user_totp("db_notenabledyet")
        assert result["totp_enabled"] is False

    def test_tenant_isolation_separate_users(self, tmp_db):
        pw = bcrypt.hashpw(b"pass", bcrypt.gensalt()).decode()
        tmp_db.create_db_user("tenant_user_a", pw, "viewer", "default")
        tmp_db.create_db_user("tenant_user_b", pw, "viewer", "default")
        tmp_db.set_user_totp_secret("tenant_user_a", "SECRETA1234567890")
        tmp_db.enable_user_totp("tenant_user_a")
        result_b = tmp_db.get_user_totp("tenant_user_b")
        assert result_b["totp_secret"] is None
        assert result_b["totp_enabled"] is False


# ─── TOTP Setup Endpoint Testleri ─────────────────────────────────


class TestTotpSetup:
    def test_setup_returns_secret_and_uri(self, tmp_db):
        _make_user(tmp_db, "setup_user1")
        headers = _auth_header("setup_user1", "viewer")
        r = client.post("/api/v1/auth/totp-setup", headers=headers)
        assert r.status_code == 200
        data = r.json()
        assert "secret" in data
        assert "otpauth_uri" in data
        assert "NetGuard" in data["otpauth_uri"]
        assert "setup_user1" in data["otpauth_uri"]

    def test_setup_without_token_returns_401(self, tmp_db):
        r = client.post("/api/v1/auth/totp-setup")
        assert r.status_code == 401

    def test_setup_secret_stored_in_db(self, tmp_db):
        _make_user(tmp_db, "setup_user2")
        headers = _auth_header("setup_user2", "viewer")
        r = client.post("/api/v1/auth/totp-setup", headers=headers)
        secret = r.json()["secret"]
        stored = tmp_db.get_user_totp("setup_user2")
        assert stored["totp_secret"] == secret
        assert stored["totp_enabled"] is False

    def test_setup_valid_base32_secret(self, tmp_db):
        _make_user(tmp_db, "setup_user3")
        headers = _auth_header("setup_user3", "viewer")
        r = client.post("/api/v1/auth/totp-setup", headers=headers)
        secret = r.json()["secret"]
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert code.isdigit() and len(code) == 6


# ─── TOTP Confirm Endpoint Testleri ───────────────────────────────


class TestTotpConfirm:
    def test_confirm_valid_code_enables_totp(self, tmp_db):
        _make_user(tmp_db, "confirm_user1")
        secret = _setup_totp(tmp_db, "confirm_user1")
        code = pyotp.TOTP(secret).now()
        token = create_access_token(username="confirm_user1", role="viewer", tenant_id="default")
        r = client.post(
            "/api/v1/auth/totp-confirm",
            json={"code": code},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        stored = tmp_db.get_user_totp("confirm_user1")
        assert stored["totp_enabled"] is True

    def test_confirm_invalid_code_returns_400(self, tmp_db):
        _make_user(tmp_db, "confirm_user2")
        _setup_totp(tmp_db, "confirm_user2")
        token = create_access_token(username="confirm_user2", role="viewer", tenant_id="default")
        r = client.post(
            "/api/v1/auth/totp-confirm",
            json={"code": "000000"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 400
        stored = tmp_db.get_user_totp("confirm_user2")
        assert stored["totp_enabled"] is False

    def test_confirm_without_setup_returns_400(self, tmp_db):
        _make_user(tmp_db, "confirm_user3")
        token = create_access_token(username="confirm_user3", role="viewer", tenant_id="default")
        r = client.post(
            "/api/v1/auth/totp-confirm",
            json={"code": "123456"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 400


# ─── Login + MFA Akış Testleri ────────────────────────────────────


class TestLoginMfaFlow:
    def test_login_without_totp_returns_full_token(self, tmp_db):
        creds = _make_user(tmp_db, "login_noMfa_user")
        r = client.post("/api/v1/auth/login", json=creds)
        assert r.status_code == 200
        data = r.json()
        assert data["mfa_required"] is False
        assert data["access_token"] is not None
        assert data["refresh_token"] is not None

    def test_login_with_totp_returns_mfa_required(self, tmp_db):
        creds = _make_user(tmp_db, "login_mfa_user")
        secret = _setup_totp(tmp_db, "login_mfa_user")
        _confirm_totp("login_mfa_user", secret)
        r = client.post("/api/v1/auth/login", json=creds)
        assert r.status_code == 200
        data = r.json()
        assert data["mfa_required"] is True
        assert data["mfa_token"] is not None
        assert data["access_token"] is None

    def test_login_mfa_token_is_valid_jwt(self, tmp_db):
        creds = _make_user(tmp_db, "login_mfa_jwt_user")
        secret = _setup_totp(tmp_db, "login_mfa_jwt_user")
        _confirm_totp("login_mfa_jwt_user", secret)
        r = client.post("/api/v1/auth/login", json=creds)
        mfa_token = r.json()["mfa_token"]
        from server.auth import verify_token
        payload = verify_token(mfa_token, token_type="mfa_pending")
        assert payload is not None
        assert payload["sub"] == "login_mfa_jwt_user"


# ─── TOTP Verify Endpoint Testleri ────────────────────────────────


class TestTotpVerify:
    def test_verify_full_flow_returns_access_token(self, tmp_db):
        creds = _make_user(tmp_db, "verify_user1")
        secret = _setup_totp(tmp_db, "verify_user1")
        _confirm_totp("verify_user1", secret)
        r_login = client.post("/api/v1/auth/login", json=creds)
        mfa_token = r_login.json()["mfa_token"]
        code = pyotp.TOTP(secret).now()
        r = client.post("/api/v1/auth/totp-verify", json={"mfa_token": mfa_token, "code": code})
        assert r.status_code == 200
        data = r.json()
        assert data["access_token"] is not None
        assert data["refresh_token"] is not None
        assert data["mfa_required"] is False

    def test_verify_wrong_code_returns_401(self, tmp_db):
        creds = _make_user(tmp_db, "verify_user2")
        secret = _setup_totp(tmp_db, "verify_user2")
        _confirm_totp("verify_user2", secret)
        r_login = client.post("/api/v1/auth/login", json=creds)
        mfa_token = r_login.json()["mfa_token"]
        r = client.post("/api/v1/auth/totp-verify", json={"mfa_token": mfa_token, "code": "000000"})
        assert r.status_code == 401

    def test_verify_invalid_mfa_token_returns_401(self, tmp_db):
        r = client.post(
            "/api/v1/auth/totp-verify",
            json={"mfa_token": "not.a.valid.token", "code": "123456"},
        )
        assert r.status_code == 401

    def test_verify_access_token_rejected_as_mfa_token(self, tmp_db):
        _make_user(tmp_db, "verify_user3")
        access_token = create_access_token(username="verify_user3", role="viewer", tenant_id="default")
        r = client.post(
            "/api/v1/auth/totp-verify",
            json={"mfa_token": access_token, "code": "123456"},
        )
        assert r.status_code == 401

    def test_verify_expired_mfa_token_returns_401(self, tmp_db):
        from jose import jwt as _jwt
        from server.auth import SECRET_KEY, ALGORITHM
        past = datetime.now(timezone.utc) - timedelta(minutes=10)
        expired_token = _jwt.encode(
            {"sub": "someuser", "role": "viewer", "tid": "default",
             "type": "mfa_pending", "exp": past, "jti": "test-jti"},
            SECRET_KEY, algorithm=ALGORITHM,
        )
        r = client.post(
            "/api/v1/auth/totp-verify",
            json={"mfa_token": expired_token, "code": "123456"},
        )
        assert r.status_code == 401

    def test_verify_returns_working_access_token(self, tmp_db):
        creds = _make_user(tmp_db, "verify_user4")
        secret = _setup_totp(tmp_db, "verify_user4")
        _confirm_totp("verify_user4", secret)
        r_login = client.post("/api/v1/auth/login", json=creds)
        mfa_token = r_login.json()["mfa_token"]
        code = pyotp.TOTP(secret).now()
        r_verify = client.post(
            "/api/v1/auth/totp-verify",
            json={"mfa_token": mfa_token, "code": code},
        )
        access_token = r_verify.json()["access_token"]
        me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"})
        assert me.status_code == 200
        assert me.json()["username"] == "verify_user4"


# ─── TOTP Disable Testleri ────────────────────────────────────────


class TestTotpDisable:
    def test_disable_allows_normal_login(self, tmp_db):
        creds = _make_user(tmp_db, "disable_user1")
        secret = _setup_totp(tmp_db, "disable_user1")
        _confirm_totp("disable_user1", secret)
        r_mfa = client.post("/api/v1/auth/login", json=creds)
        assert r_mfa.json()["mfa_required"] is True
        token = create_access_token(username="disable_user1", role="viewer", tenant_id="default")
        client.post("/api/v1/auth/totp-disable", headers={"Authorization": f"Bearer {token}"})
        r_normal = client.post("/api/v1/auth/login", json=creds)
        assert r_normal.status_code == 200
        assert r_normal.json()["mfa_required"] is False
        assert r_normal.json()["access_token"] is not None

    def test_disable_clears_db(self, tmp_db):
        _make_user(tmp_db, "disable_user2")
        secret = _setup_totp(tmp_db, "disable_user2")
        _confirm_totp("disable_user2", secret)
        token = create_access_token(username="disable_user2", role="viewer", tenant_id="default")
        client.post("/api/v1/auth/totp-disable", headers={"Authorization": f"Bearer {token}"})
        stored = tmp_db.get_user_totp("disable_user2")
        assert stored["totp_enabled"] is False
        assert stored["totp_secret"] is None

    def test_admin_can_disable_other_user(self, tmp_db):
        _make_user(tmp_db, "disable_target")
        secret = _setup_totp(tmp_db, "disable_target")
        _confirm_totp("disable_target", secret)
        admin_token = create_access_token(username="admin", role="admin", tenant_id="default")
        r = client.post(
            "/api/v1/auth/totp-disable?target_username=disable_target",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        stored = tmp_db.get_user_totp("disable_target")
        assert stored["totp_enabled"] is False

    def test_viewer_cannot_disable_other_user(self, tmp_db):
        _make_user(tmp_db, "disable_victim")
        _make_user(tmp_db, "disable_attacker")
        secret = _setup_totp(tmp_db, "disable_victim")
        _confirm_totp("disable_victim", secret)
        viewer_token = create_access_token(username="disable_attacker", role="viewer", tenant_id="default")
        r = client.post(
            "/api/v1/auth/totp-disable?target_username=disable_victim",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 403

    def test_disable_without_auth_returns_401(self, tmp_db):
        r = client.post("/api/v1/auth/totp-disable")
        assert r.status_code == 401


# ─── create_mfa_token birim testleri ──────────────────────────────


class TestCreateMfaToken:
    def test_mfa_token_type_is_mfa_pending(self):
        from server.auth import verify_token
        token = create_mfa_token("testuser", "viewer", "default")
        payload = verify_token(token, token_type="mfa_pending")
        assert payload is not None
        assert payload["sub"] == "testuser"
        assert payload["type"] == "mfa_pending"

    def test_mfa_token_rejected_as_access(self):
        from server.auth import verify_token
        token = create_mfa_token("testuser", "viewer", "default")
        payload = verify_token(token, token_type="access")
        assert payload is None

    def test_mfa_token_carries_tenant_id(self):
        from server.auth import verify_token
        token = create_mfa_token("user1", "admin", "tenant_xyz")
        payload = verify_token(token, token_type="mfa_pending")
        assert payload["tid"] == "tenant_xyz"
