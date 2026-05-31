"""U3 — Tamperproof audit log (SHA-256 hash chain) testleri.

NIST SP 800-92 §3.2 + NIS2 Article 21(2)(i) gereksinimlerine uygunluk.
"""

import hashlib
import json
import threading
import pytest
from fastapi.testclient import TestClient

from server.database import _audit_content, _AUDIT_CHAIN_GENESIS


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def db_instance(tmp_db):
    return tmp_db


@pytest.fixture
def client(tmp_db, admin_token, monkeypatch):
    monkeypatch.setattr("server.routes.maintenance.db", tmp_db)
    from server.main import app
    return TestClient(app), admin_token, tmp_db


# ── Yardımcı: hash yeniden hesaplama ──────────────────────────────────────────

def _recompute_hash(row: dict, previous_hash: str) -> str:
    from datetime import timezone
    ts = row["timestamp"]
    ts_str = ts.astimezone(timezone.utc).isoformat() if hasattr(ts, "astimezone") else str(ts)
    content = _audit_content(
        row["event_id"], row["actor"], row["action"], row["resource"],
        row["detail"] or "", row["ip_address"] or "",
        ts_str, previous_hash,
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ── Hash Üretim Testleri ───────────────────────────────────────────────────────

class TestAuditHashGeneration:
    def test_entry_hash_populated(self, db_instance):
        db_instance.save_audit_event("admin", "test_action", "/res")
        events = db_instance.get_audit_log(limit=10)
        assert events[0]["entry_hash"] is not None
        assert len(events[0]["entry_hash"]) == 64

    def test_previous_hash_genesis(self, db_instance):
        db_instance.save_audit_event("admin", "first_action", "/res")
        events = db_instance.get_audit_log(limit=10)
        assert events[0]["previous_hash"] == _AUDIT_CHAIN_GENESIS

    def test_second_entry_links_to_first(self, db_instance):
        db_instance.save_audit_event("admin", "action_1", "/a")
        db_instance.save_audit_event("admin", "action_2", "/b")
        events = db_instance.get_audit_log(limit=10)
        events_asc = list(reversed(events))
        assert events_asc[1]["previous_hash"] == events_asc[0]["entry_hash"]

    def test_hash_is_deterministic(self, db_instance):
        db_instance.save_audit_event("user1", "login", "session")
        row = db_instance.get_audit_log(limit=1)[0]
        recomputed = _recompute_hash(row, row["previous_hash"])
        assert recomputed == row["entry_hash"]

    def test_hash_covers_all_fields(self, db_instance):
        db_instance.save_audit_event("actor_x", "action_y", "resource_z", "detail_w", "1.2.3.4")
        row = db_instance.get_audit_log(limit=1)[0]
        assert row["actor"] == "actor_x"
        assert row["action"] == "action_y"
        assert row["resource"] == "resource_z"
        assert row["detail"] == "detail_w"
        assert row["ip_address"] == "1.2.3.4"
        recomputed = _recompute_hash(row, row["previous_hash"])
        assert recomputed == row["entry_hash"]

    def test_entry_hash_is_hex_sha256(self, db_instance):
        db_instance.save_audit_event("admin", "check_type", "/")
        row = db_instance.get_audit_log(limit=1)[0]
        assert all(c in "0123456789abcdef" for c in row["entry_hash"])
        assert len(row["entry_hash"]) == 64

    def test_delimiter_injection_distinct_hashes(self, db_instance):
        """Hash input JSON canonical → delimiter injection üretmez ayrı hash'ler."""
        db_instance.save_audit_event("admin|extra", "legit", "/r")
        db_instance.save_audit_event("admin", "extra|legit", "/r")
        events = list(reversed(db_instance.get_audit_log(limit=10)))
        assert events[0]["entry_hash"] != events[1]["entry_hash"]


# ── Zincir Bütünlük Testleri ──────────────────────────────────────────────────

class TestAuditChainIntegrity:
    def test_empty_db_valid(self, db_instance):
        result = db_instance.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 0

    def test_single_entry_valid(self, db_instance):
        db_instance.save_audit_event("admin", "login", "/session")
        result = db_instance.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 1

    def test_chain_of_five_valid(self, db_instance):
        for i in range(5):
            db_instance.save_audit_event("admin", f"action_{i}", f"/res/{i}")
        result = db_instance.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 5

    def test_tampered_entry_hash_detected(self, db_instance):
        db_instance.save_audit_event("admin", "action_1", "/a")
        db_instance.save_audit_event("admin", "action_2", "/b")
        with db_instance._connect() as conn:
            conn.execute("UPDATE audit_log SET entry_hash='deadbeef' || substr(entry_hash,9) WHERE action='action_1'")
        result = db_instance.verify_audit_chain()
        assert result["valid"] is False
        assert result["first_broken_at"] is not None

    def test_tampered_field_detected(self, db_instance):
        db_instance.save_audit_event("admin", "legitimate_action", "/resource")
        with db_instance._connect() as conn:
            conn.execute("UPDATE audit_log SET actor='attacker' WHERE action='legitimate_action'")
        result = db_instance.verify_audit_chain()
        assert result["valid"] is False

    def test_deleted_entry_breaks_chain(self, db_instance):
        for i in range(3):
            db_instance.save_audit_event("admin", f"a{i}", f"/r{i}")
        with db_instance._connect() as conn:
            row = conn.execute("SELECT id FROM audit_log ORDER BY id ASC LIMIT 1").fetchone()
            conn.execute("DELETE FROM audit_log WHERE id=%s", (row["id"],))
        result = db_instance.verify_audit_chain()
        assert result["valid"] is False

    def test_legacy_null_entries_skipped(self, db_instance):
        with db_instance._connect() as conn:
            conn.execute(
                "INSERT INTO audit_log (event_id, actor, action, resource, timestamp) "
                "VALUES ('old-uuid', 'admin', 'legacy_action', '/old', '2025-01-01T00:00:00+00:00')"
            )
        db_instance.save_audit_event("admin", "new_action", "/new")
        result = db_instance.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 1
        assert result["skipped"] == 1

    def test_first_broken_at_points_to_correct_id(self, db_instance):
        for i in range(4):
            db_instance.save_audit_event("admin", f"act{i}", f"/r{i}")
        with db_instance._connect() as conn:
            row = conn.execute(
                "SELECT id FROM audit_log ORDER BY id ASC LIMIT 1 OFFSET 2"
            ).fetchone()
            tampered_id = row["id"]
            conn.execute(
                "UPDATE audit_log SET entry_hash=%s WHERE id=%s", ("0" * 64, tampered_id)
            )
        result = db_instance.verify_audit_chain()
        assert result["valid"] is False
        assert result["first_broken_at"] == tampered_id

    def test_concurrent_writes_no_chain_fork(self, db_instance):
        """10 paralel thread: her biri save_audit_event çağırır → chain fork olmaz."""
        errors = []
        def write(i):
            try:
                db_instance.save_audit_event("thread", f"action_{i}", f"/res/{i}")
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=write, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        result = db_instance.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 10


# ── Verify API Endpoint Testleri ──────────────────────────────────────────────

class TestVerifyEndpoint:
    def test_verify_empty_returns_valid(self, client):
        tc, token, _ = client
        resp = tc.get("/api/v1/audit-log/verify", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["checked"] == 0

    def test_verify_after_events_returns_valid(self, client):
        tc, token, test_db = client
        test_db.save_audit_event("admin", "block_ip", "10.0.0.1")
        test_db.save_audit_event("admin", "unblock_ip", "10.0.0.1")
        resp = tc.get("/api/v1/audit-log/verify", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["checked"] == 2

    def test_verify_requires_auth(self, client):
        tc, _, _ = client
        resp = tc.get("/api/v1/audit-log/verify")
        assert resp.status_code == 401

    def test_verify_tampered_returns_invalid(self, client):
        tc, token, test_db = client
        test_db.save_audit_event("admin", "original_action", "/target")
        with test_db._connect() as conn:
            conn.execute("UPDATE audit_log SET actor='hacker' WHERE action='original_action'")
        resp = tc.get("/api/v1/audit-log/verify", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        assert data["first_broken_at"] is not None

    def test_verify_response_schema(self, client):
        tc, token, _ = client
        resp = tc.get("/api/v1/audit-log/verify", headers={"Authorization": f"Bearer {token}"})
        data = resp.json()
        assert "valid" in data
        assert "checked" in data
        assert "skipped" in data
        assert "first_broken_at" in data
        assert "message" in data


# ── PostgreSQL Smoke Testleri ─────────────────────────────────────────────────

class TestAuditChainPostgres:
    """PostgreSQL ortamında hash chain doğrulama — testcontainers gerektirir."""

    def test_pg_save_and_verify_chain(self, pg_db):
        """PG: 3 kayıt yaz, zincir geçerli olmalı."""
        pg_db.save_audit_event("admin", "pg_action_1", "/res/1", "detail1", "10.0.0.1")
        pg_db.save_audit_event("user1", "pg_action_2", "/res/2")
        pg_db.save_audit_event("system", "pg_action_3", "/res/3", ip_address="192.168.1.1")
        result = pg_db.verify_audit_chain()
        assert result["valid"] is True
        assert result["checked"] == 3

    def test_pg_chain_links_correctly(self, pg_db):
        """PG: 2. kaydın previous_hash, 1. kaydın entry_hash'ine eşit olmalı."""
        pg_db.save_audit_event("admin", "first", "/a")
        pg_db.save_audit_event("admin", "second", "/b")
        events = pg_db.get_audit_log(limit=10)
        events_asc = list(reversed(events))
        assert events_asc[1]["previous_hash"] == events_asc[0]["entry_hash"]

    def test_pg_tamper_detected(self, pg_db):
        """PG: actor alanı değiştirilirse verify False döner."""
        pg_db.save_audit_event("admin", "sensitive_action", "/critical")
        with pg_db._connect() as conn:
            conn.execute("UPDATE audit_log SET actor='attacker' WHERE action='sensitive_action'")
        result = pg_db.verify_audit_chain()
        assert result["valid"] is False
