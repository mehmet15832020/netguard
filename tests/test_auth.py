"""
Authentication testleri.
"""

from fastapi.testclient import TestClient
from server.main import app
from server.auth import register_agent_key, create_access_token

client = TestClient(app)


class TestLogin:
    def test_login_success(self):
        response = client.post("/api/v1/auth/login", json={
            "username": "admin",
            "password": "netguard123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self):
        response = client.post("/api/v1/auth/login", json={
            "username": "admin",
            "password": "yanlis_sifre"
        })
        assert response.status_code == 401

    def test_login_unknown_user(self):
        response = client.post("/api/v1/auth/login", json={
            "username": "olmayan_kullanici",
            "password": "sifre"
        })
        assert response.status_code == 401


class TestProtectedEndpoints:
    def _get_token(self) -> str:
        response = client.post("/api/v1/auth/login", json={
            "username": "admin",
            "password": "netguard123"
        })
        return response.json()["access_token"]

    def test_me_without_token_returns_401(self):
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401

    def test_me_with_token_returns_user(self):
        token = self._get_token()
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200
        assert response.json()["username"] == "admin"
        assert response.json()["role"] == "admin"

    def test_viewer_cannot_create_agent_key(self):
        response = client.post("/api/v1/auth/login", json={
            "username": "viewer",
            "password": "viewer123"
        })
        token = response.json()["access_token"]

        response = client.post(
            "/api/v1/auth/agent-key?agent_id=test",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 403


class TestRefreshToken:
    def test_refresh_flow(self):
        from server.auth import create_access_token, create_refresh_token

        access  = create_access_token("admin", "admin")
        refresh = create_refresh_token("admin", "admin")

        # Geçerli refresh token → yeni token çifti
        r = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
        assert r.status_code == 200
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data

        # Yeni access token ile /me çalışmalı
        me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
        assert me.status_code == 200
        assert me.json()["username"] == "admin"

        # Access token refresh endpoint'inde reddedilmeli
        r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": access})
        assert r2.status_code == 401

    def test_invalid_refresh_token_rejected(self):
        r = client.post("/api/v1/auth/refresh", json={"refresh_token": "not.a.valid.token"})
        assert r.status_code == 401


class TestLogout:
    def test_logout_blacklists_token(self, tmp_db):
        access = create_access_token("admin", "admin")
        headers = {"Authorization": f"Bearer {access}"}

        # Logout
        r = client.post("/api/v1/auth/logout", headers=headers)
        assert r.status_code == 200

        # Aynı token artık geçersiz olmalı
        me = client.get("/api/v1/auth/me", headers=headers)
        assert me.status_code == 401

    def test_logout_without_token_returns_403(self):
        r = client.post("/api/v1/auth/logout")
        assert r.status_code in (401, 403)


class TestApiKey:
    def test_agent_key_generation(self, tmp_db):
        key = register_agent_key("test-agent-hash-001")
        assert key is not None
        assert len(key) > 20

    def test_key_stored_as_hash(self, tmp_db):
        from server.database import db
        from server.auth import _hash_api_key
        key = register_agent_key("test-agent-hash-002")
        stored = db.get_api_key("test-agent-hash-002")
        assert stored == _hash_api_key(key)
        assert stored != key

    def test_duplicate_registration_returns_none(self, tmp_db):
        register_agent_key("test-agent-dup")
        second = register_agent_key("test-agent-dup")
        assert second is None

    def test_verify_api_key(self, tmp_db):
        from server.auth import verify_api_key
        key = register_agent_key("test-agent-verify")
        assert verify_api_key(key) == "test-agent-verify"
        assert verify_api_key("wrong-key") is None