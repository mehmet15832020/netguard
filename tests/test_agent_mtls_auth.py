"""
A3 — server/auth.py::get_agent_identity_verified() testleri.

nginx'in gerçek TLS handshake doğrulamasını pytest test edemez (TestClient
nginx'in önünden geçmez) — bu testler nginx'in *ileteceği* X-SSL-Client-*
header'larını manuel simüle ederek FastAPI dependency mantığını doğrular.
Gerçek nginx mTLS yapılandırması için CLAUDE.md'deki manuel doğrulama
prosedürüne (openssl s_client) bakın.
"""

import importlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from server.agent_pki import issue_agent_certificate
from server.auth import register_agent_key
from server.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_ca_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_CA_DIR", str(tmp_path / "agent_ca"))


def _agent_api_key(agent_id: str) -> str:
    key = register_agent_key(agent_id)
    assert key is not None
    return key


def _metrics_payload(agent_id: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "agent_id": agent_id,
        "hostname": "test-host",
        "collected_at": now,
        "status": "online",
        "cpu": {"usage_percent": 10.0, "core_count": 4, "load_avg_1m": 0.5},
        "memory": {
            "total_bytes": 8_000_000_000, "used_bytes": 2_000_000_000,
            "available_bytes": 6_000_000_000, "usage_percent": 25.0,
        },
        "disks": [], "network_interfaces": [],
    }


class TestNoMtlsHeaders:
    """nginx mTLS yapılandırılmamış / lab ortamı — API-key-only fallback."""

    def test_metrics_accepted_with_api_key_only(self, tmp_db):
        api_key = _agent_api_key("agent-fallback")
        resp = client.post(
            "/api/v1/agents/metrics",
            json=_metrics_payload("agent-fallback"),
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 202


class TestMtlsRequired:
    """AGENT_MTLS_REQUIRED=true iken mTLS header'ı yoksa reddedilmeli."""

    def test_rejected_without_mtls_header(self, tmp_db, monkeypatch):
        import server.auth as auth_module
        monkeypatch.setattr(auth_module, "AGENT_MTLS_REQUIRED", True)
        api_key = _agent_api_key("agent-strict")
        resp = client.post(
            "/api/v1/agents/metrics",
            json=_metrics_payload("agent-strict"),
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 401


class TestMtlsVerification:
    def test_accepted_when_cn_matches_and_cert_active(self, tmp_db, monkeypatch):
        from server.database import db
        agent_id = "agent-mtls-ok"
        api_key = _agent_api_key(agent_id)
        _, _, serial, fingerprint, expires_at = issue_agent_certificate(agent_id)
        db.save_agent_certificate(agent_id, serial, fingerprint, expires_at)

        resp = client.post(
            "/api/v1/agents/metrics",
            json=_metrics_payload(agent_id),
            headers={
                "X-API-Key": api_key,
                "X-SSL-Client-Verify": "SUCCESS",
                "X-SSL-Client-CN": agent_id,
                "X-SSL-Client-Serial": format(int(serial), "X"),
            },
        )
        assert resp.status_code == 202

    def test_rejected_when_verify_failed(self, tmp_db):
        agent_id = "agent-mtls-fail"
        api_key = _agent_api_key(agent_id)
        resp = client.post(
            "/api/v1/agents/metrics",
            json=_metrics_payload(agent_id),
            headers={
                "X-API-Key": api_key,
                "X-SSL-Client-Verify": "FAILED:unable to verify the first certificate",
                "X-SSL-Client-CN": agent_id,
            },
        )
        assert resp.status_code == 401

    def test_rejected_when_cn_mismatches_agent_id(self, tmp_db):
        """API key 'victim'e ait ama sertifika CN'i 'attacker' — impersonation girişimi."""
        victim_id = "agent-victim"
        api_key = _agent_api_key(victim_id)
        resp = client.post(
            "/api/v1/agents/metrics",
            json=_metrics_payload(victim_id),
            headers={
                "X-API-Key": api_key,
                "X-SSL-Client-Verify": "SUCCESS",
                "X-SSL-Client-CN": "agent-attacker",
            },
        )
        assert resp.status_code == 403

    def test_rejected_when_certificate_revoked(self, tmp_db):
        from server.database import db
        agent_id = "agent-revoked"
        api_key = _agent_api_key(agent_id)
        _, _, serial, fingerprint, expires_at = issue_agent_certificate(agent_id)
        db.save_agent_certificate(agent_id, serial, fingerprint, expires_at)
        db.revoke_agent_certificate(agent_id, serial)

        resp = client.post(
            "/api/v1/agents/metrics",
            json=_metrics_payload(agent_id),
            headers={
                "X-API-Key": api_key,
                "X-SSL-Client-Verify": "SUCCESS",
                "X-SSL-Client-CN": agent_id,
                "X-SSL-Client-Serial": format(int(serial), "X"),
            },
        )
        assert resp.status_code == 403

    def test_rejected_when_certificate_unknown_to_db(self, tmp_db):
        """nginx sertifikayı doğruladı ama DB'de bu serial hiç kayıtlı değil."""
        agent_id = "agent-unknown-cert"
        api_key = _agent_api_key(agent_id)
        resp = client.post(
            "/api/v1/agents/metrics",
            json=_metrics_payload(agent_id),
            headers={
                "X-API-Key": api_key,
                "X-SSL-Client-Verify": "SUCCESS",
                "X-SSL-Client-CN": agent_id,
                "X-SSL-Client-Serial": "DEADBEEF",
            },
        )
        assert resp.status_code == 403


class TestAgentKeyEndpointIssuesCertificate:
    def test_create_agent_key_returns_certificate(self, tmp_db, admin_token):
        resp = client.post(
            "/api/v1/auth/agent-key?agent_id=agent-new-cert",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "client_cert_pem" in data
        assert "client_key_pem" in data
        assert "cert_expires_at" in data
        assert "BEGIN CERTIFICATE" in data["client_cert_pem"]

    def test_delete_agent_key_revokes_certificates(self, tmp_db, admin_token):
        from server.database import db
        agent_id = "agent-to-delete"
        headers = {"Authorization": f"Bearer {admin_token}"}
        client.post(f"/api/v1/auth/agent-key?agent_id={agent_id}", headers=headers)

        resp = client.delete(f"/api/v1/auth/agent-key/{agent_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["certificates_revoked"] == 1

    def test_revoke_cert_endpoint_keeps_api_key(self, tmp_db, admin_token):
        from server.database import db
        agent_id = "agent-revoke-only"
        headers = {"Authorization": f"Bearer {admin_token}"}
        client.post(f"/api/v1/auth/agent-key?agent_id={agent_id}", headers=headers)

        resp = client.post(f"/api/v1/auth/agent-key/{agent_id}/revoke-cert", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["certificates_revoked"] == 1
        assert db.get_api_key(agent_id) is not None
