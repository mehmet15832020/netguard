"""
Authentication testleri.
"""

from fastapi.testclient import TestClient
from server.main import app
from server.auth import register_agent_key

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


class TestApiKey:
    def test_agent_key_generation(self):
        key = register_agent_key("test-agent-123")
        assert len(key) > 20

    def test_same_agent_gets_same_key(self):
        key1 = register_agent_key("agent-abc")
        key2 = register_agent_key("agent-abc")
        assert key1 == key2