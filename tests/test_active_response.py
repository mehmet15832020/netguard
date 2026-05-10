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
        monkeypatch.setattr(OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: BlockResult(True, "opnsense"))
        vyos_called = []
        monkeypatch.setattr(VyOSProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: vyos_called.append(ip) or BlockResult(True, "vyos"))

        mgr = ActiveResponseManager()
        mgr.block_ip("1.2.3.4", "test", "admin", tenant_id="default")

        assert len(vyos_called) == 0

    def test_opnsense_fail_vyos_called(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: BlockResult(False, "opnsense", "credentials eksik"))
        vyos_called = []
        monkeypatch.setattr(VyOSProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: vyos_called.append(ip) or BlockResult(True, "vyos"))

        mgr = ActiveResponseManager()
        mgr.block_ip("1.2.3.4", "test", "admin", tenant_id="default")

        assert "1.2.3.4" in vyos_called

    def test_both_fail_returns_failure(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: BlockResult(False, "opnsense", "fail"))
        monkeypatch.setattr(VyOSProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: BlockResult(False, "vyos", "fail"))

        mgr = ActiveResponseManager()
        result = mgr.block_ip("1.2.3.4", "test", "admin", tenant_id="default")

        assert result["success"] is False
        assert tmp_db.is_ip_blocked("1.2.3.4", tenant_id="default") is False

    def test_block_saves_to_db(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: BlockResult(True, "opnsense"))

        mgr = ActiveResponseManager()
        result = mgr.block_ip("5.6.7.8", "brute force", "admin", tenant_id="default")

        assert result["success"] is True
        assert tmp_db.is_ip_blocked("5.6.7.8", tenant_id="default") is True
        record = tmp_db.get_block_by_ip("5.6.7.8", tenant_id="default")
        assert record["reason"] == "brute force"
        assert record["provider"] == "opnsense"

    def test_block_saves_audit_log(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: BlockResult(True, "opnsense"))

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
        monkeypatch.setattr(OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: BlockResult(True, "opnsense"))
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
        monkeypatch.setattr(OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: BlockResult(True, "opnsense"))
        r = client.post("/api/v1/response/block",
                        json={"ip": "203.0.113.1", "reason": "port scan detected"},
                        headers=_admin_auth())
        assert r.status_code == 201
        data = r.json()
        assert data["success"] is True
        assert data["provider"] == "opnsense"

    def test_block_duplicate(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: BlockResult(True, "opnsense"))
        client.post("/api/v1/response/block",
                    json={"ip": "203.0.113.2", "reason": "first block"},
                    headers=_admin_auth())
        r = client.post("/api/v1/response/block",
                        json={"ip": "203.0.113.2", "reason": "duplicate"},
                        headers=_admin_auth())
        assert r.status_code == 409

    def test_list_blocks_empty(self, tmp_db):
        r = client.get("/api/v1/response/blocks", headers=_admin_auth())
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 0
        assert data["blocks"] == []

    def test_list_blocks_populated(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: BlockResult(True, "opnsense"))
        client.post("/api/v1/response/block",
                    json={"ip": "203.0.113.3", "reason": "scan"},
                    headers=_admin_auth())
        r = client.get("/api/v1/response/blocks", headers=_admin_auth())
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1
        assert data["blocks"][0]["ip"] == "203.0.113.3"

    def test_unblock_success(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: BlockResult(True, "opnsense"))
        monkeypatch.setattr(OPNsenseProvider, "unblock", lambda self, ip: UnblockResult(True, "opnsense"))
        client.post("/api/v1/response/block",
                    json={"ip": "203.0.113.4", "reason": "scan"},
                    headers=_admin_auth())
        r = client.delete("/api/v1/response/block/203.0.113.4", headers=_admin_auth())
        assert r.status_code == 200

        r2 = client.get("/api/v1/response/blocks", headers=_admin_auth())
        assert r2.json()["count"] == 0

    def test_unblock_not_found(self, tmp_db, monkeypatch):
        monkeypatch.setattr(OPNsenseProvider, "unblock", lambda self, ip: UnblockResult(True, "opnsense"))
        r = client.delete("/api/v1/response/block/203.0.113.99", headers=_admin_auth())
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


# ═══════════════════════════════════════════════════════════════════════════ #
#  P1 — RFC1918 Koruması
# ═══════════════════════════════════════════════════════════════════════════ #

class TestRFC1918Protection:
    """P1: RFC1918 ve kritik IP'lerin bloklama öncesi reddedilmesi."""

    def _admin_headers(self):
        from server.auth import create_access_token
        token = create_access_token("admin", "superadmin", tenant_id="default")
        return {"Authorization": f"Bearer {token}"}

    @pytest.mark.parametrize("ip,label", [
        ("10.0.0.1",      "RFC1918 class-A"),
        ("172.16.0.1",    "RFC1918 class-B"),
        ("192.168.1.1",   "RFC1918 class-C"),
        ("127.0.0.1",     "loopback"),
        ("169.254.0.1",   "link-local"),
    ])
    def test_protected_ip_blocked(self, tmp_db, ip, label):
        response = client.post(
            "/api/v1/response/block",
            json={"ip": ip, "reason": f"test {label}"},
            headers=self._admin_headers(),
        )
        assert response.status_code == 400, f"{label} ({ip}) bloklanmamalıydı"
        assert "korumalı" in response.json()["detail"]

    def test_public_ip_not_blocked_by_protection(self, tmp_db, monkeypatch):
        """Genel IP koruması tetiklememeli (provider başarısız olsa da 400 değil 502 döner)."""
        from server import active_response as ar_mod
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: ar_mod.BlockResult(False, "opnsense", "test"))
        monkeypatch.setattr(ar_mod.VyOSProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: ar_mod.BlockResult(False, "vyos", "test"))
        response = client.post(
            "/api/v1/response/block",
            json={"ip": "8.8.8.8", "reason": "test genel ip"},
            headers=self._admin_headers(),
        )
        assert response.status_code == 502


# ═══════════════════════════════════════════════════════════════════════════ #
#  P2 — TTL / Auto-Expiry
# ═══════════════════════════════════════════════════════════════════════════ #

class TestTTLExpiry:
    """P2: TTL / auto-expiry mekanizması."""

    def test_block_with_ttl_stores_expires_at(self, tmp_db):
        from server.database import db
        db.block_ip("ttl-test-001", "1.2.3.4", "test", "admin",
                    provider="opnsense", tenant_id="default", ttl_hours=24)
        record = db.get_block_by_ip("1.2.3.4", "default")
        assert record is not None
        assert record["expires_at"] is not None

    def test_block_without_ttl_has_no_expires_at(self, tmp_db):
        from server.database import db
        db.block_ip("no-ttl-001", "2.3.4.5", "test", "admin",
                    provider="opnsense", tenant_id="default")
        record = db.get_block_by_ip("2.3.4.5", "default")
        assert record is not None
        assert record["expires_at"] is None

    def test_get_expired_blocks_returns_past_expiry(self, tmp_db):
        from server.database import db
        from datetime import datetime, timezone, timedelta
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        import sqlite3
        with sqlite3.connect(tmp_db._path) as conn:
            conn.execute(
                """INSERT INTO blocked_ips
                   (block_id, ip, reason, blocked_by, blocked_at, is_active, provider, tenant_id, expires_at)
                   VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)""",
                ("expired-001", "3.4.5.6", "test", "admin",
                 datetime.now(timezone.utc).isoformat(),
                 "opnsense", "default", past),
            )
        expired = db.get_expired_blocks()
        ips = [r["ip"] for r in expired]
        assert "3.4.5.6" in ips

    def test_get_expired_blocks_excludes_future_expiry(self, tmp_db):
        from server.database import db
        db.block_ip("future-001", "4.5.6.7", "test", "admin",
                    provider="opnsense", tenant_id="default", ttl_hours=24)
        expired = db.get_expired_blocks()
        ips = [r["ip"] for r in expired]
        assert "4.5.6.7" not in ips

    def test_expire_blocks_calls_unblock(self, tmp_db, monkeypatch):
        from server.database import db
        from server.active_response import ActiveResponseManager
        import sqlite3
        from datetime import datetime, timezone, timedelta

        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with sqlite3.connect(tmp_db._path) as conn:
            conn.execute(
                """INSERT INTO blocked_ips
                   (block_id, ip, reason, blocked_by, blocked_at, is_active, provider, tenant_id, expires_at)
                   VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)""",
                ("exp-mgr-001", "5.6.7.8", "test", "admin",
                 datetime.now(timezone.utc).isoformat(),
                 "opnsense", "default", past),
            )

        mgr = ActiveResponseManager()
        from server import active_response as ar_mod
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "unblock",
                            lambda self, ip: ar_mod.UnblockResult(True, "opnsense"))
        monkeypatch.setattr(mgr, "_opnsense", ar_mod.OPNsenseProvider())

        count = mgr.expire_blocks()
        assert count == 1
        assert not db.is_ip_blocked("5.6.7.8", "default")

    def test_ttl_via_api_endpoint(self, tmp_db, monkeypatch):
        from server.auth import create_access_token
        from server import active_response as ar_mod
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: ar_mod.BlockResult(True, "opnsense"))
        token = create_access_token("admin", "superadmin", tenant_id="default")
        response = client.post(
            "/api/v1/response/block",
            json={"ip": "8.8.4.4", "reason": "test ttl", "ttl_hours": 2.0},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201
        from server.database import db
        record = db.get_block_by_ip("8.8.4.4", "default")
        assert record["expires_at"] is not None


# ═══════════════════════════════════════════════════════════════════════════ #
#  P3 — FP Manager Bloklama Öncesi Kontrol
# ═══════════════════════════════════════════════════════════════════════════ #

class TestFPGate:
    """P3: FP manager blok öncesi kontrol."""

    def _admin_headers(self):
        from server.auth import create_access_token
        token = create_access_token("admin", "superadmin", tenant_id="default")
        return {"Authorization": f"Bearer {token}"}

    def test_fp_suppressed_ip_rejected(self, tmp_db, monkeypatch):
        """FP kuralıyla eşleşen IP bloklama reddedilmeli (409)."""
        from server.fp_manager import fp_manager
        monkeypatch.setattr(fp_manager, "is_suppressed",
                            lambda *a, **kw: "fp-rule-test-001")
        response = client.post(
            "/api/v1/response/block",
            json={"ip": "203.0.113.10", "reason": "test"},
            headers=self._admin_headers(),
        )
        assert response.status_code == 409
        assert "FP kuralıyla" in response.json()["detail"]

    def test_fp_suppressed_ip_force_override(self, tmp_db, monkeypatch):
        """force=True ile FP eşleşmesi bypass edilebilmeli."""
        from server.fp_manager import fp_manager
        from server import active_response as ar_mod
        monkeypatch.setattr(fp_manager, "is_suppressed",
                            lambda *a, **kw: "fp-rule-test-002")
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: ar_mod.BlockResult(True, "opnsense"))
        response = client.post(
            "/api/v1/response/block",
            json={"ip": "203.0.113.11", "reason": "test force", "force": True},
            headers=self._admin_headers(),
        )
        assert response.status_code == 201

    def test_no_fp_match_proceeds_normally(self, tmp_db, monkeypatch):
        """FP eşleşmesi yoksa bloklama normal devam etmeli."""
        from server.fp_manager import fp_manager
        from server import active_response as ar_mod
        monkeypatch.setattr(fp_manager, "is_suppressed",
                            lambda *a, **kw: None)
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: ar_mod.BlockResult(True, "opnsense"))
        response = client.post(
            "/api/v1/response/block",
            json={"ip": "203.0.113.12", "reason": "test no fp"},
            headers=self._admin_headers(),
        )
        assert response.status_code == 201


# ═══════════════════════════════════════════════════════════════════════════ #
#  P4 — Incident Severity Gate
# ═══════════════════════════════════════════════════════════════════════════ #

class TestSeverityGate:
    """P4: Incident severity threshold."""

    def _admin_headers(self):
        from server.auth import create_access_token
        token = create_access_token("admin", "superadmin", tenant_id="default")
        return {"Authorization": f"Bearer {token}"}

    def _make_incident(self, tmp_db, severity: str) -> str:
        """Test incident oluştur, ID'yi döndür."""
        from server.database import db
        import uuid
        incident = Incident(
            incident_id=str(uuid.uuid4()),
            title=f"Test incident {severity}",
            severity=severity,
            created_by="system",
            group_value="203.0.113.50",
            rule_id="test-rule",
        )
        db.create_incident(incident, tenant_id="default")
        return incident.incident_id

    def test_medium_severity_incident_rejected(self, tmp_db, monkeypatch):
        """medium severity incident'ı bloklama reddedilmeli (422)."""
        from server.fp_manager import fp_manager
        monkeypatch.setattr(fp_manager, "is_suppressed", lambda *a, **kw: None)
        inc_id = self._make_incident(tmp_db, "medium")
        response = client.post(
            "/api/v1/response/block",
            json={"ip": "203.0.113.20", "reason": "test", "source_incident_id": inc_id},
            headers=self._admin_headers(),
        )
        assert response.status_code == 422
        assert "minimum" in response.json()["detail"]

    def test_critical_severity_incident_allowed(self, tmp_db, monkeypatch):
        """critical severity incident'ı bloklama geçmeli."""
        from server.fp_manager import fp_manager
        from server import active_response as ar_mod
        monkeypatch.setattr(fp_manager, "is_suppressed", lambda *a, **kw: None)
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: ar_mod.BlockResult(True, "opnsense"))
        inc_id = self._make_incident(tmp_db, "critical")
        response = client.post(
            "/api/v1/response/block",
            json={"ip": "203.0.113.21", "reason": "test", "source_incident_id": inc_id},
            headers=self._admin_headers(),
        )
        assert response.status_code == 201

    def test_no_incident_id_bypasses_severity_gate(self, tmp_db, monkeypatch):
        """source_incident_id verilmezse severity gate devreye girmemeli."""
        from server.fp_manager import fp_manager
        from server import active_response as ar_mod
        monkeypatch.setattr(fp_manager, "is_suppressed", lambda *a, **kw: None)
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: ar_mod.BlockResult(True, "opnsense"))
        response = client.post(
            "/api/v1/response/block",
            json={"ip": "203.0.113.22", "reason": "manual block"},
            headers=self._admin_headers(),
        )
        assert response.status_code == 201

    def test_block_min_severity_env_configurable(self, tmp_db, monkeypatch):
        """BLOCK_MIN_SEVERITY=critical ile high severity reddedilmeli."""
        from server.fp_manager import fp_manager
        monkeypatch.setattr(fp_manager, "is_suppressed", lambda *a, **kw: None)
        monkeypatch.setenv("BLOCK_MIN_SEVERITY", "critical")
        inc_id = self._make_incident(tmp_db, "high")
        response = client.post(
            "/api/v1/response/block",
            json={"ip": "203.0.113.23", "reason": "test env", "source_incident_id": inc_id},
            headers=self._admin_headers(),
        )
        assert response.status_code == 422


class TestProgressiveTTL:
    """P5: Repeated offenders / progressive TTL mekanizması."""

    def test_first_offense_gets_default_ttl(self):
        from server.active_response import _progressive_ttl
        ttl = _progressive_ttl(1)
        assert ttl == 1.0

    def test_second_offense_gets_longer_ttl(self):
        from server.active_response import _progressive_ttl
        assert _progressive_ttl(2) > _progressive_ttl(1)

    def test_beyond_max_offense_uses_last_value(self):
        from server.active_response import _progressive_ttl
        assert _progressive_ttl(100) == _progressive_ttl(4)

    def test_offense_count_increments_on_reblock(self, tmp_db, monkeypatch):
        """Aynı IP iki kez bloklandığında offense_count 2 olmalı."""
        from server.database import db
        from server import active_response as ar_mod
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: ar_mod.BlockResult(True, "opnsense"))
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "unblock",
                            lambda self, ip: ar_mod.UnblockResult(True, "opnsense"))

        mgr = ar_mod.ActiveResponseManager()
        mgr.block_ip("203.0.113.30", "first block", "admin", tenant_id="default")
        mgr.unblock_ip("203.0.113.30", "admin", tenant_id="default")
        mgr.block_ip("203.0.113.30", "second block", "admin", tenant_id="default")

        record = db.get_block_by_ip("203.0.113.30", "default")
        assert record is not None
        assert record["offense_count"] == 2

    def test_progressive_ttl_env_override(self, monkeypatch):
        """BLOCK_PROGRESSIVE_TTL env değişkeni ile özel TTL listesi."""
        monkeypatch.setenv("BLOCK_PROGRESSIVE_TTL", "0.5,2,12,72")
        from server import active_response as ar_mod
        ttl_list = ar_mod._parse_progressive_ttl()
        assert ttl_list == [0.5, 2.0, 12.0, 72.0]
        assert ar_mod._progressive_ttl(1) == 0.5
        assert ar_mod._progressive_ttl(2) == 2.0

    def test_explicit_ttl_overrides_progressive(self, tmp_db, monkeypatch):
        """Admin açıkça ttl_hours verirse progressive bypass edilmeli."""
        from server.database import db
        from server import active_response as ar_mod
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "block",
                            lambda self, ip, dst_port=None, proto=None: ar_mod.BlockResult(True, "opnsense"))

        mgr = ar_mod.ActiveResponseManager()
        mgr.block_ip("203.0.113.31", "explicit ttl", "admin",
                     tenant_id="default", ttl_hours=99.0)

        record = db.get_block_by_ip("203.0.113.31", "default")
        assert record is not None
        from datetime import datetime, timezone, timedelta
        expires = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
        delta = expires - datetime.now(timezone.utc)
        assert 98 < delta.total_seconds() / 3600 < 100

    def test_offense_count_stored_in_db(self, tmp_db):
        """Yeni blok kaydında offense_count DB'ye yazılmalı."""
        from server.database import db
        db.block_ip("off-cnt-001", "203.0.113.32", "test", "admin",
                    provider="opnsense", tenant_id="default",
                    ttl_hours=1.0, offense_count=3)
        record = db.get_block_by_ip("203.0.113.32", "default")
        assert record["offense_count"] == 3


# ═══════════════════════════════════════════════════════════════════════════ #
#  P6 — Blok Doğrulama (Firewall ↔ DB Senkronizasyonu)
# ═══════════════════════════════════════════════════════════════════════════ #

class TestBlockVerification:
    """P6: Firewall ile DB blok senkronizasyon doğrulaması."""

    def _admin_headers(self):
        from server.auth import create_access_token
        token = create_access_token("admin", "superadmin", tenant_id="default")
        return {"Authorization": f"Bearer {token}"}

    def test_verify_returns_ok_when_synced(self, tmp_db, monkeypatch):
        from server import active_response as ar_mod
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "list_blocked",
                            lambda self: ["203.0.113.40"])
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "_ready",
                            lambda self: True)
        from server.database import db
        db.block_ip("verify-001", "203.0.113.40", "test", "admin",
                    provider="opnsense", tenant_id="default")

        response = client.get("/api/v1/response/blocks/verify",
                              headers=self._admin_headers())
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "203.0.113.40" in data["synced"]
        assert data["phantom"] == []
        assert data["orphan"] == []

    def test_verify_detects_phantom(self, tmp_db, monkeypatch):
        from server import active_response as ar_mod
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "list_blocked",
                            lambda self: [])
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "_ready",
                            lambda self: True)
        from server.database import db
        db.block_ip("phantom-001", "203.0.113.41", "test", "admin",
                    provider="opnsense", tenant_id="default")

        response = client.get("/api/v1/response/blocks/verify",
                              headers=self._admin_headers())
        data = response.json()
        assert data["status"] == "mismatch"
        assert "203.0.113.41" in data["phantom"]

    def test_verify_detects_orphan(self, tmp_db, monkeypatch):
        from server import active_response as ar_mod
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "list_blocked",
                            lambda self: ["203.0.113.42"])
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "_ready",
                            lambda self: True)

        response = client.get("/api/v1/response/blocks/verify",
                              headers=self._admin_headers())
        data = response.json()
        assert data["status"] == "mismatch"
        assert "203.0.113.42" in data["orphan"]


# ═══════════════════════════════════════════════════════════════════════════ #
#  P7 — Port/Protocol Granülaritesi
# ═══════════════════════════════════════════════════════════════════════════ #

class TestPortProtocolBlock:
    """P7: Port/protocol granülaritesi."""

    def _admin_headers(self):
        from server.auth import create_access_token
        token = create_access_token("admin", "superadmin", tenant_id="default")
        return {"Authorization": f"Bearer {token}"}

    def test_block_with_port_uses_rule_api(self, tmp_db, monkeypatch):
        from server import active_response as ar_mod
        called = {}

        def fake_rule(self, client, ip, port, proto):
            called["port"] = port
            called["proto"] = proto
            return ar_mod.BlockResult(True, "opnsense")

        monkeypatch.setattr(ar_mod.OPNsenseProvider, "_block_with_rule", fake_rule)
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "_ready", lambda self: True)

        response = client.post(
            "/api/v1/response/block",
            json={"ip": "203.0.113.50", "reason": "smb block",
                  "destination_port": 445, "network_protocol": "tcp"},
            headers=self._admin_headers(),
        )
        assert response.status_code == 201
        assert called.get("port") == 445
        assert called.get("proto") == "tcp"

    def test_block_without_port_uses_alias(self, tmp_db, monkeypatch):
        from server import active_response as ar_mod
        called = {}

        def fake_alias_block(self, ip, destination_port=None, network_protocol=None):
            called["used_alias"] = True
            return ar_mod.BlockResult(True, "opnsense")

        monkeypatch.setattr(ar_mod.OPNsenseProvider, "block", fake_alias_block)

        response = client.post(
            "/api/v1/response/block",
            json={"ip": "203.0.113.51", "reason": "full block"},
            headers=self._admin_headers(),
        )
        assert response.status_code == 201
        assert called.get("used_alias")

    def test_invalid_port_rejected(self, tmp_db):
        response = client.post(
            "/api/v1/response/block",
            json={"ip": "203.0.113.52", "reason": "test", "destination_port": 99999},
            headers=self._admin_headers(),
        )
        assert response.status_code == 422

    def test_invalid_protocol_rejected(self, tmp_db):
        response = client.post(
            "/api/v1/response/block",
            json={"ip": "203.0.113.53", "reason": "test", "network_protocol": "ftp"},
            headers=self._admin_headers(),
        )
        assert response.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════ #
#  P8 — Break-Glass Mekanizması
# ═══════════════════════════════════════════════════════════════════════════ #

class TestBreakGlass:
    """P8: Break-glass acil unblock mekanizması."""

    def test_break_glass_disabled_without_env(self, tmp_db, monkeypatch):
        monkeypatch.delenv("BREAK_GLASS_TOKEN", raising=False)
        import server.routes.active_response as ar_route
        monkeypatch.setattr(ar_route, "_BREAK_GLASS_TOKEN", "")
        response = client.delete(
            "/api/v1/response/break-glass/203.0.113.60",
            headers={"x-break-glass-token": "anything"},
        )
        assert response.status_code == 503

    def test_break_glass_wrong_token_rejected(self, tmp_db, monkeypatch):
        import server.routes.active_response as ar_route
        monkeypatch.setattr(ar_route, "_BREAK_GLASS_TOKEN", "correct-token")
        response = client.delete(
            "/api/v1/response/break-glass/203.0.113.61",
            headers={"x-break-glass-token": "wrong-token"},
        )
        assert response.status_code == 401

    def test_break_glass_unblocks_ip(self, tmp_db, monkeypatch):
        from server.database import db
        from server import active_response as ar_mod
        import server.routes.active_response as ar_route

        monkeypatch.setattr(ar_route, "_BREAK_GLASS_TOKEN", "emergency-token")
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "unblock",
                            lambda self, ip: ar_mod.UnblockResult(True, "opnsense"))

        db.block_ip("bg-001", "203.0.113.62", "test", "admin",
                    provider="opnsense", tenant_id="default")

        response = client.delete(
            "/api/v1/response/break-glass/203.0.113.62",
            headers={"x-break-glass-token": "emergency-token"},
        )
        assert response.status_code == 200
        assert not db.is_ip_blocked("203.0.113.62", "default")

    def test_break_glass_audit_log_written(self, tmp_db, monkeypatch):
        from server.database import db
        from server import active_response as ar_mod
        import server.routes.active_response as ar_route

        monkeypatch.setattr(ar_route, "_BREAK_GLASS_TOKEN", "audit-token")
        monkeypatch.setattr(ar_mod.OPNsenseProvider, "unblock",
                            lambda self, ip: ar_mod.UnblockResult(True, "opnsense"))

        db.block_ip("bg-002", "203.0.113.63", "test", "admin",
                    provider="opnsense", tenant_id="default")

        client.delete(
            "/api/v1/response/break-glass/203.0.113.63",
            headers={"x-break-glass-token": "audit-token"},
        )
        logs = db.get_audit_log(limit=5)
        actions = [l["action"] for l in logs]
        assert "ip_unblocked_break_glass" in actions
