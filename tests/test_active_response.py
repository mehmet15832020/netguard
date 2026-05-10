"""
NetGuard — V1-9 Aktif Yanıt testleri

Birim  : OPNsenseProvider, VyOSProvider
Çapraz : ActiveResponseManager (provider seçimi, DB yazma)
Entegrasyon: HTTP endpoint'leri (/response/block, /response/blocks, vb.)
"""

import uuid
import pytest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from server.main import app
from server.auth import create_access_token
from server.active_response import (
    OPNsenseProvider, VyOSProvider, ActiveResponseManager,
    BlockResult, UnblockResult,
)
from shared.models import Incident, IncidentStatus

client = TestClient(app)


def _admin_auth() -> dict:
    token = create_access_token(username="admin", role="admin", tenant_id="default")
    return {"Authorization": f"Bearer {token}"}


def _viewer_auth() -> dict:
    token = create_access_token(username="viewer", role="viewer", tenant_id="default")
    return {"Authorization": f"Bearer {token}"}


# ═══════════════════════════════════════════════════════════════════════════ #
#  Birim — OPNsenseProvider
# ═══════════════════════════════════════════════════════════════════════════ #

class TestOPNsenseProvider:

    def test_block_returns_failure_when_credentials_missing(self, monkeypatch):
        monkeypatch.delenv("OPNSENSE_HOST", raising=False)
        monkeypatch.delenv("OPNSENSE_KEY", raising=False)
        monkeypatch.delenv("OPNSENSE_SECRET", raising=False)
        provider = OPNsenseProvider()
        result = provider.block("1.2.3.4")
        assert result.success is False
        assert result.provider == "opnsense"

    def test_unblock_returns_failure_when_credentials_missing(self, monkeypatch):
        monkeypatch.delenv("OPNSENSE_HOST", raising=False)
        monkeypatch.delenv("OPNSENSE_KEY", raising=False)
        monkeypatch.delenv("OPNSENSE_SECRET", raising=False)
        provider = OPNsenseProvider()
        result = provider.unblock("1.2.3.4")
        assert result.success is False
        assert result.provider == "opnsense"

    def test_block_success(self, monkeypatch):
        monkeypatch.setenv("OPNSENSE_HOST", "10.0.30.1")
        monkeypatch.setenv("OPNSENSE_KEY", "key123")
        monkeypatch.setenv("OPNSENSE_SECRET", "secret123")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "OK"

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response

        with patch("httpx.Client", return_value=mock_client):
            provider = OPNsenseProvider()
            result = provider.block("1.2.3.4")

        assert result.success is True
        assert result.provider == "opnsense"
        assert result.error == ""

    def test_block_http_error(self, monkeypatch):
        monkeypatch.setenv("OPNSENSE_HOST", "10.0.30.1")
        monkeypatch.setenv("OPNSENSE_KEY", "key123")
        monkeypatch.setenv("OPNSENSE_SECRET", "secret123")

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response

        with patch("httpx.Client", return_value=mock_client):
            provider = OPNsenseProvider()
            result = provider.block("1.2.3.4")

        assert result.success is False
        assert "HTTP 500" in result.error

    def test_block_exception_handled(self, monkeypatch):
        monkeypatch.setenv("OPNSENSE_HOST", "10.0.30.1")
        monkeypatch.setenv("OPNSENSE_KEY", "key123")
        monkeypatch.setenv("OPNSENSE_SECRET", "secret123")

        with patch("httpx.Client", side_effect=Exception("Connection refused")):
            provider = OPNsenseProvider()
            result = provider.block("1.2.3.4")

        assert result.success is False
        assert "Connection refused" in result.error


# ═══════════════════════════════════════════════════════════════════════════ #
#  Birim — VyOSProvider
# ═══════════════════════════════════════════════════════════════════════════ #

class TestVyOSProvider:

    def test_block_returns_failure_when_credentials_missing(self, monkeypatch):
        monkeypatch.delenv("VYOS_HOST", raising=False)
        monkeypatch.delenv("VYOS_KEY_PATH", raising=False)
        provider = VyOSProvider()
        result = provider.block("1.2.3.4")
        assert result.success is False
        assert result.provider == "vyos"

    def test_unblock_returns_failure_when_credentials_missing(self, monkeypatch):
        monkeypatch.delenv("VYOS_HOST", raising=False)
        monkeypatch.delenv("VYOS_KEY_PATH", raising=False)
        provider = VyOSProvider()
        result = provider.unblock("1.2.3.4")
        assert result.success is False
        assert result.provider == "vyos"

    def test_block_paramiko_import_error(self, monkeypatch):
        monkeypatch.setenv("VYOS_HOST", "192.168.203.200")
        monkeypatch.setenv("VYOS_KEY_PATH", "/home/user/.ssh/id_ed25519")
        provider = VyOSProvider()

        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "paramiko":
                raise ImportError("No module named 'paramiko'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        ok, msg = provider._exec(["show version"])
        assert ok is False
        assert "paramiko" in msg

    def test_block_ssh_exception(self, monkeypatch):
        monkeypatch.setenv("VYOS_HOST", "192.168.203.200")
        monkeypatch.setenv("VYOS_KEY_PATH", "/home/user/.ssh/id_ed25519")
        provider = VyOSProvider()

        monkeypatch.setattr(provider, "_exec", lambda cmds: (False, "Connection refused"))
        result = provider.block("1.2.3.4")
        assert result.success is False
        assert "Connection refused" in result.error


# ═══════════════════════════════════════════════════════════════════════════ #
#  Çapraz — ActiveResponseManager
# ═══════════════════════════════════════════════════════════════════════════ #

class TestActiveResponseManager:

    def test_opnsense_success_vyos_not_called(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block", lambda self, ip: BlockResult(True, "opnsense"))
        vyos_called = []
        monkeypatch.setattr(VyOSProvider, "block", lambda self, ip: vyos_called.append(ip) or BlockResult(True, "vyos"))

        mgr = ActiveResponseManager()
        mgr.block_ip("1.2.3.4", "test", "admin", tenant_id="default")

        assert len(vyos_called) == 0

    def test_opnsense_fail_vyos_called(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block", lambda self, ip: BlockResult(False, "opnsense", "credentials eksik"))
        vyos_called = []
        monkeypatch.setattr(VyOSProvider, "block", lambda self, ip: vyos_called.append(ip) or BlockResult(True, "vyos"))

        mgr = ActiveResponseManager()
        mgr.block_ip("1.2.3.4", "test", "admin", tenant_id="default")

        assert "1.2.3.4" in vyos_called

    def test_both_fail_returns_failure(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block", lambda self, ip: BlockResult(False, "opnsense", "fail"))
        monkeypatch.setattr(VyOSProvider, "block", lambda self, ip: BlockResult(False, "vyos", "fail"))

        mgr = ActiveResponseManager()
        result = mgr.block_ip("1.2.3.4", "test", "admin", tenant_id="default")

        assert result["success"] is False
        assert tmp_db.is_ip_blocked("1.2.3.4", tenant_id="default") is False

    def test_block_saves_to_db(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block", lambda self, ip: BlockResult(True, "opnsense"))

        mgr = ActiveResponseManager()
        result = mgr.block_ip("5.6.7.8", "brute force", "admin", tenant_id="default")

        assert result["success"] is True
        assert tmp_db.is_ip_blocked("5.6.7.8", tenant_id="default") is True
        record = tmp_db.get_block_by_ip("5.6.7.8", tenant_id="default")
        assert record["reason"] == "brute force"
        assert record["provider"] == "opnsense"

    def test_block_saves_audit_log(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block", lambda self, ip: BlockResult(True, "opnsense"))

        mgr = ActiveResponseManager()
        mgr.block_ip("9.10.11.12", "scan detected", "admin", tenant_id="default")

        audit = tmp_db.get_audit_log(limit=10)
        actions = [a["action"] for a in audit]
        assert "ip_blocked" in actions

    def test_unblock_uses_correct_provider(self, tmp_db, monkeypatch):
        block_id = str(uuid.uuid4())
        tmp_db.block_ip(block_id, "1.2.3.4", "reason", "admin",
                        provider="vyos", tenant_id="default")

        opnsense_called = []
        vyos_called = []
        monkeypatch.setattr(OPNsenseProvider, "unblock", lambda self, ip: opnsense_called.append(ip) or UnblockResult(True, "opnsense"))
        monkeypatch.setattr(VyOSProvider, "unblock", lambda self, ip: vyos_called.append(ip) or UnblockResult(True, "vyos"))

        mgr = ActiveResponseManager()
        result = mgr.unblock_ip("1.2.3.4", "admin", tenant_id="default")

        assert result["success"] is True
        assert "1.2.3.4" in vyos_called
        assert len(opnsense_called) == 0


# ═══════════════════════════════════════════════════════════════════════════ #
#  Entegrasyon — HTTP endpoint'leri
# ═══════════════════════════════════════════════════════════════════════════ #

class TestActiveResponseEndpoints:

    def test_block_requires_admin(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block", lambda self, ip: BlockResult(True, "opnsense"))
        r = client.post("/api/v1/response/block",
                        json={"ip": "1.2.3.4", "reason": "test"},
                        headers=_viewer_auth())
        assert r.status_code == 403

    def test_block_unauthenticated(self, tmp_db):
        r = client.post("/api/v1/response/block",
                        json={"ip": "1.2.3.4", "reason": "test"})
        assert r.status_code == 401

    def test_block_invalid_ip(self, tmp_db):
        r = client.post("/api/v1/response/block",
                        json={"ip": "abc.def.ghi.jkl", "reason": "test"},
                        headers=_admin_auth())
        assert r.status_code == 422

    def test_block_empty_reason(self, tmp_db):
        r = client.post("/api/v1/response/block",
                        json={"ip": "1.2.3.4", "reason": ""},
                        headers=_admin_auth())
        assert r.status_code == 422

    def test_block_success(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block", lambda self, ip: BlockResult(True, "opnsense"))
        r = client.post("/api/v1/response/block",
                        json={"ip": "10.0.0.1", "reason": "port scan detected"},
                        headers=_admin_auth())
        assert r.status_code == 201
        data = r.json()
        assert data["success"] is True
        assert data["provider"] == "opnsense"

    def test_block_duplicate(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block", lambda self, ip: BlockResult(True, "opnsense"))
        client.post("/api/v1/response/block",
                    json={"ip": "10.0.0.2", "reason": "first block"},
                    headers=_admin_auth())
        r = client.post("/api/v1/response/block",
                        json={"ip": "10.0.0.2", "reason": "duplicate"},
                        headers=_admin_auth())
        assert r.status_code == 409

    def test_list_blocks_empty(self, tmp_db):
        r = client.get("/api/v1/response/blocks", headers=_admin_auth())
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 0
        assert data["blocks"] == []

    def test_list_blocks_populated(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block", lambda self, ip: BlockResult(True, "opnsense"))
        client.post("/api/v1/response/block",
                    json={"ip": "10.0.0.3", "reason": "scan"},
                    headers=_admin_auth())
        r = client.get("/api/v1/response/blocks", headers=_admin_auth())
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1
        assert data["blocks"][0]["ip"] == "10.0.0.3"

    def test_unblock_success(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block", lambda self, ip: BlockResult(True, "opnsense"))
        monkeypatch.setattr(OPNsenseProvider, "unblock", lambda self, ip: UnblockResult(True, "opnsense"))
        client.post("/api/v1/response/block",
                    json={"ip": "10.0.0.4", "reason": "scan"},
                    headers=_admin_auth())
        r = client.delete("/api/v1/response/block/10.0.0.4", headers=_admin_auth())
        assert r.status_code == 200

        r2 = client.get("/api/v1/response/blocks", headers=_admin_auth())
        assert r2.json()["count"] == 0

    def test_unblock_not_found(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "unblock", lambda self, ip: UnblockResult(True, "opnsense"))
        r = client.delete("/api/v1/response/block/10.0.0.99", headers=_admin_auth())
        assert r.status_code == 404

    def test_playbook_critical_with_ip(self, tmp_db):
        incident = Incident(
            incident_id=str(uuid.uuid4()),
            title="Full Attack Chain",
            severity="critical",
            created_by="system",
            group_value="192.168.1.100",
            rule_id="full_attack_chain",
        )
        tmp_db.create_incident(incident, tenant_id="default")

        r = client.post("/api/v1/response/playbook",
                        json={"incident_id": incident.incident_id},
                        headers=_admin_auth())
        assert r.status_code == 200
        data = r.json()
        assert len(data["suggestions"]) == 1
        assert data["suggestions"][0]["action"] == "block_ip"
        assert data["suggestions"][0]["ip"] == "192.168.1.100"
        assert data["suggestions"][0]["already_blocked"] is False

    def test_playbook_warning_no_suggestion(self, tmp_db):
        incident = Incident(
            incident_id=str(uuid.uuid4()),
            title="Low severity event",
            severity="warning",
            created_by="system",
            group_value="192.168.1.200",
            rule_id="ssh_brute_force",
        )
        tmp_db.create_incident(incident, tenant_id="default")

        r = client.post("/api/v1/response/playbook",
                        json={"incident_id": incident.incident_id},
                        headers=_admin_auth())
        assert r.status_code == 200
        data = r.json()
        assert data["suggestions"] == []

    def test_playbook_incident_not_found(self, tmp_db):
        r = client.post("/api/v1/response/playbook",
                        json={"incident_id": "nonexistent-id-xyz"},
                        headers=_admin_auth())
        assert r.status_code == 404
