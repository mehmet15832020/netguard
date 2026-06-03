"""N7 — Dead Rule Detection testleri.

GET /api/v1/sigma/rules/quality?days=N endpoint'i:
- Tüm sigma kurallarını listeler
- Her kural için hit_count + last_hit + quality_status döner
- dead: enabled + 0 hit; active: hit var; disabled: devre dışı
"""

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from server.main import app

client = TestClient(app)


def _auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


def _make_rule_meta(rule_id: str, enabled: bool = True, title: str = "") -> dict:
    return {
        "rule_id":  rule_id,
        "title":    title or rule_id,
        "status":   "stable",
        "description": "",
        "level":    "medium",
        "tags":     [],
        "falsepositives": [],
        "enabled":  enabled,
        "filename": f"{rule_id}.yml" if enabled else f"{rule_id}.yml.disabled",
    }


def _insert_hit(tmp_db, rule_id: str, ts: datetime = None):
    """correlated_events tablosuna bir hit ekle."""
    ts = ts or datetime.now(timezone.utc)
    with tmp_db._connect() as conn:
        conn.execute(
            """INSERT INTO correlated_events
               (corr_id, tenant_id, rule_id, rule_name, event_action, severity,
                group_value, matched_count, window_seconds,
                first_seen, last_seen, message, created_at)
               VALUES (%s,'default',%s,'Test Rule','test','medium',
                       '1.1.1.1', 1, 300, %s, %s, 'test hit', %s)""",
            (str(uuid.uuid4()), rule_id, ts, ts, ts),
        )


# ── 1. Temel uç nokta çağrısı ─────────────────────────────────────────────

class TestQualityEndpointBasic:
    def test_returns_200(self, admin_token, tmp_db):
        with patch("server.routes.sigma._list_sigma_files", return_value=[]), \
             patch("server.routes.sigma._parse_v2_rule", return_value=None):
            r = client.get("/api/v1/sigma/rules/quality", headers=_auth(admin_token))
        assert r.status_code == 200

    def test_summary_keys_present(self, admin_token, tmp_db):
        with patch("server.routes.sigma._list_sigma_files", return_value=[]):
            r = client.get("/api/v1/sigma/rules/quality", headers=_auth(admin_token))
        data = r.json()
        assert "summary" in data
        assert "dead_rules" in data
        assert "active_rules" in data

    def test_requires_auth(self, tmp_db):
        r = client.get("/api/v1/sigma/rules/quality")
        assert r.status_code == 401

    def test_invalid_days_422(self, admin_token, tmp_db):
        r = client.get("/api/v1/sigma/rules/quality?days=0", headers=_auth(admin_token))
        assert r.status_code == 422

    def test_days_too_large_422(self, admin_token, tmp_db):
        r = client.get("/api/v1/sigma/rules/quality?days=999", headers=_auth(admin_token))
        assert r.status_code == 422


# ── 2. Ölü kural tespiti ──────────────────────────────────────────────────

class TestDeadRuleDetection:
    def test_rule_with_no_hits_is_dead(self, admin_token, tmp_db):
        mock_path = MagicMock(spec=Path)
        meta = _make_rule_meta("ng_dead_rule")
        with patch("server.routes.sigma._list_sigma_files", return_value=[mock_path]), \
             patch("server.routes.sigma._parse_v2_rule", return_value=meta):
            r = client.get("/api/v1/sigma/rules/quality?days=30", headers=_auth(admin_token))
        data = r.json()
        assert data["summary"]["dead"] == 1
        assert data["dead_rules"][0]["rule_id"] == "ng_dead_rule"
        assert data["dead_rules"][0]["quality_status"] == "dead"

    def test_rule_with_hits_is_active(self, admin_token, tmp_db):
        rule_id = "ng_active_rule"
        _insert_hit(tmp_db, rule_id)

        mock_path = MagicMock(spec=Path)
        meta = _make_rule_meta(rule_id)
        with patch("server.routes.sigma._list_sigma_files", return_value=[mock_path]), \
             patch("server.routes.sigma._parse_v2_rule", return_value=meta):
            r = client.get("/api/v1/sigma/rules/quality?days=30", headers=_auth(admin_token))
        data = r.json()
        assert data["summary"]["active"] == 1
        assert data["active_rules"][0]["quality_status"] == "active"
        assert data["active_rules"][0]["hit_count"] >= 1

    def test_disabled_rule_is_disabled(self, admin_token, tmp_db):
        mock_path = MagicMock(spec=Path)
        meta = _make_rule_meta("ng_disabled_rule", enabled=False)
        with patch("server.routes.sigma._list_sigma_files", return_value=[mock_path]), \
             patch("server.routes.sigma._parse_v2_rule", return_value=meta):
            r = client.get("/api/v1/sigma/rules/quality?days=30", headers=_auth(admin_token))
        data = r.json()
        assert data["summary"]["disabled"] == 1

    def test_last_hit_returned_for_active_rule(self, admin_token, tmp_db):
        rule_id = "ng_hit_time_rule"
        ts = datetime.now(timezone.utc) - timedelta(hours=3)
        _insert_hit(tmp_db, rule_id, ts)

        mock_path = MagicMock(spec=Path)
        meta = _make_rule_meta(rule_id)
        with patch("server.routes.sigma._list_sigma_files", return_value=[mock_path]), \
             patch("server.routes.sigma._parse_v2_rule", return_value=meta):
            r = client.get("/api/v1/sigma/rules/quality?days=30", headers=_auth(admin_token))
        data = r.json()
        active = data["active_rules"][0]
        assert active["last_hit"] is not None

    def test_hit_outside_window_counts_as_dead(self, admin_token, tmp_db):
        rule_id = "ng_old_hit_rule"
        old_ts = datetime.now(timezone.utc) - timedelta(days=40)
        _insert_hit(tmp_db, rule_id, old_ts)

        mock_path = MagicMock(spec=Path)
        meta = _make_rule_meta(rule_id)
        with patch("server.routes.sigma._list_sigma_files", return_value=[mock_path]), \
             patch("server.routes.sigma._parse_v2_rule", return_value=meta):
            r = client.get("/api/v1/sigma/rules/quality?days=30", headers=_auth(admin_token))
        data = r.json()
        assert data["summary"]["dead"] == 1

    def test_mixed_rules(self, admin_token, tmp_db):
        active_id = "ng_active_m"
        dead_id   = "ng_dead_m"
        _insert_hit(tmp_db, active_id)

        paths = [MagicMock(spec=Path), MagicMock(spec=Path)]
        metas = [_make_rule_meta(active_id), _make_rule_meta(dead_id)]
        with patch("server.routes.sigma._list_sigma_files", return_value=paths), \
             patch("server.routes.sigma._parse_v2_rule", side_effect=metas):
            r = client.get("/api/v1/sigma/rules/quality?days=30", headers=_auth(admin_token))
        data = r.json()
        assert data["summary"]["active"] == 1
        assert data["summary"]["dead"] == 1

    def test_window_days_in_response(self, admin_token, tmp_db):
        with patch("server.routes.sigma._list_sigma_files", return_value=[]):
            r = client.get("/api/v1/sigma/rules/quality?days=7", headers=_auth(admin_token))
        assert r.json()["window_days"] == 7
