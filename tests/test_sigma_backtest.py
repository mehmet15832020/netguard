"""
F1 — Sigma Rule Backtest Engine testleri.

POST /api/v1/sigma/rules/{rule_id}/backtest

Üç test grubu:
  1. _inject_backtest_window — birim (DB yok)
  2. SigmaExecutor.execute_backtest — birim (PG bağımlı, tmp_db)
  3. Backtest route — entegrasyon (tmp_db + sigma_dir)
"""

import textwrap
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from server.main import app
from server.sigma_executor import (
    SigmaExecutableRule,
    SigmaExecutor,
    _inject_backtest_window,
)
import server.routes.sigma as sigma_mod

client = TestClient(app)

_RULE_ID = "bb000001-cccc-4ddd-8eee-ffffffffffff"
_CORR_YAML = textwrap.dedent(f"""\
    title: BF Base
    name: ng_bf_backtest_base
    status: test
    logsource:
        category: authentication
    detection:
        selection:
            event_action: ssh_failure
        condition: selection
    level: low
    ---
    title: SSH Brute Force Backtest
    id: {_RULE_ID}
    correlation:
        type: event_count
        rules: ng_bf_backtest_base
        group-by:
            - source_ip
        timespan: 5m
        condition:
            gte: 3
    level: high
    tags:
        - attack.t1110
""")

_DET_ID = "dd000001-aaaa-4bbb-8ccc-eeeeeeeeeeee"
_DET_YAML = textwrap.dedent(f"""\
    title: SSH Failure Detection
    id: {_DET_ID}
    status: test
    logsource:
        category: authentication
    detection:
        selection:
            event_action: ssh_failure
        condition: selection
    level: medium
    tags:
        - attack.t1110
""")


@pytest.fixture()
def sigma_dir(tmp_path, monkeypatch):
    d = tmp_path / "sigma_rules_v2"
    d.mkdir()
    (d / f"{_RULE_ID}.yml").write_text(_CORR_YAML)
    (d / f"{_DET_ID}.yml").write_text(_DET_YAML)
    monkeypatch.setattr(sigma_mod, "SIGMA_DIR", d)
    return d


# ─── 1. _inject_backtest_window birim testleri ────────────────────────────────


class TestInjectBacktestWindow:
    def test_simple_detection_sql_replaces_now(self):
        sql = (
            "SELECT * FROM normalized_logs WHERE event_action = 'ssh_failure'"
            " AND timestamp >= NOW() - INTERVAL '60 seconds'"
        )
        result, count = _inject_backtest_window(sql)
        assert count == 1
        assert "NOW()" not in result
        assert "timestamp >= %s AND timestamp <= %s" in result

    def test_correlation_subquery_replaces_now(self):
        sql = (
            "SELECT source_ip, COUNT(*) AS event_count FROM ("
            "SELECT * FROM normalized_logs WHERE event_action = 'x'"
            " AND timestamp >= NOW() - INTERVAL '300 seconds'"
            ") AS subquery GROUP BY source_ip HAVING COUNT(*) >= 5"
        )
        result, count = _inject_backtest_window(sql)
        assert count == 1
        assert "NOW()" not in result
        assert "timestamp >= %s AND timestamp <= %s" in result

    def test_sql_without_now_unchanged(self):
        sql = "SELECT * FROM normalized_logs WHERE event_action = 'x'"
        result, count = _inject_backtest_window(sql)
        assert count == 0
        assert result == sql

    def test_returns_correct_replacement_count(self):
        sql = (
            "SELECT * FROM normalized_logs WHERE x = 1"
            " AND timestamp >= NOW() - INTERVAL '60 seconds'"
        )
        _, count = _inject_backtest_window(sql)
        assert count == 1

    def test_original_sql_not_mutated(self):
        sql = "SELECT * FROM normalized_logs WHERE x AND timestamp >= NOW() - INTERVAL '60 seconds'"
        original = sql
        _inject_backtest_window(sql)
        assert sql == original


# ─── 2. execute_backtest birim testleri ──────────────────────────────────────


class TestExecuteBacktest:
    def _make_rule(self, is_corr: bool = False) -> SigmaExecutableRule:
        if is_corr:
            sql = (
                "SELECT source_ip, COUNT(*) AS event_count,"
                " MIN(subquery.timestamp) AS first_ts, MAX(subquery.timestamp) AS last_ts"
                " FROM (SELECT * FROM normalized_logs WHERE event_action = 'ssh_failure'"
                " AND timestamp >= NOW() - INTERVAL '300 seconds') AS subquery"
                " GROUP BY source_ip HAVING COUNT(*) >= 1"
            )
            return SigmaExecutableRule(
                rule_id="test-corr",
                title="Test Correlation",
                severity="high",
                sql=sql,
                window_seconds=300,
                group_by_fields=["source_ip"],
                is_correlation=True,
            )
        sql = (
            "SELECT * FROM normalized_logs WHERE event_action = 'ssh_failure'"
            " AND timestamp >= NOW() - INTERVAL '60 seconds'"
        )
        return SigmaExecutableRule(
            rule_id="test-det",
            title="Test Detection",
            severity="medium",
            sql=sql,
            window_seconds=60,
            group_by_fields=[],
            is_correlation=False,
        )

    def test_invalid_tenant_returns_empty(self, tmp_db):
        rule = self._make_rule()
        executor = SigmaExecutor.__new__(SigmaExecutor)
        executor._rules = [rule]
        with tmp_db._connect() as conn:
            result = executor.execute_backtest(
                rule, conn, "invalid tenant!", datetime.now(timezone.utc) - timedelta(hours=1), datetime.now(timezone.utc)
            )
        assert result == []

    def test_rule_without_time_filter_returns_empty(self, tmp_db):
        rule = SigmaExecutableRule(
            rule_id="no-time",
            title="No Time",
            severity="info",
            sql="SELECT * FROM normalized_logs WHERE event_action = 'x'",
            window_seconds=60,
            group_by_fields=[],
            is_correlation=False,
        )
        executor = SigmaExecutor.__new__(SigmaExecutor)
        with tmp_db._connect() as conn:
            result = executor.execute_backtest(
                rule, conn, "default", datetime.now(timezone.utc) - timedelta(hours=1), datetime.now(timezone.utc)
            )
        assert result == []

    def test_detection_rule_returns_matches(self, tmp_db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(minutes=30)).isoformat()
        with tmp_db._connect() as conn:
            conn.execute(
                "INSERT INTO normalized_logs (log_id, raw_id, source_type, observer_hostname,"
                " timestamp, received_at, processed_at, severity, event_category, event_action,"
                " source_ip, destination_ip, message, tags, tenant_id)"
                " VALUES (%s,%s,'auth','host',%s,%s,%s,'high','auth','ssh_failure',"
                "'10.0.0.1','10.0.0.2','test','[]','default')",
                [str(uuid.uuid4()), str(uuid.uuid4()), ts, ts, ts],
            )

        rule = self._make_rule(is_corr=False)
        executor = SigmaExecutor.__new__(SigmaExecutor)
        with tmp_db._connect() as conn:
            results = executor.execute_backtest(
                rule, conn, "default",
                now - timedelta(hours=1), now,
            )
        assert len(results) == 1
        assert results[0]["group_value"] == "10.0.0.1"
        assert results[0]["event_count"] == 1

    def test_correlation_rule_returns_event_count(self, tmp_db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(minutes=30)).isoformat()
        with tmp_db._connect() as conn:
            for _ in range(4):
                conn.execute(
                    "INSERT INTO normalized_logs (log_id, raw_id, source_type, observer_hostname,"
                    " timestamp, received_at, processed_at, severity, event_category, event_action,"
                    " source_ip, destination_ip, message, tags, tenant_id)"
                    " VALUES (%s,%s,'auth','host',%s,%s,%s,'high','auth','ssh_failure',"
                    "'10.0.0.5','10.0.0.2','test','[]','default')",
                    [str(uuid.uuid4()), str(uuid.uuid4()), ts, ts, ts],
                )

        rule = self._make_rule(is_corr=True)
        executor = SigmaExecutor.__new__(SigmaExecutor)
        with tmp_db._connect() as conn:
            results = executor.execute_backtest(
                rule, conn, "default",
                now - timedelta(hours=1), now,
            )
        assert len(results) == 1
        assert results[0]["group_value"] == "10.0.0.5"
        assert results[0]["event_count"] == 4

    def test_no_match_returns_empty_list(self, tmp_db):
        now = datetime.now(timezone.utc)
        rule = self._make_rule(is_corr=False)
        executor = SigmaExecutor.__new__(SigmaExecutor)
        with tmp_db._connect() as conn:
            results = executor.execute_backtest(
                rule, conn, "default",
                now - timedelta(hours=2), now - timedelta(hours=1),
            )
        assert results == []

    def test_tenant_isolation(self, tmp_db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(minutes=30)).isoformat()
        with tmp_db._connect() as conn:
            conn.execute(
                "INSERT INTO tenants (id, name) VALUES ('other', 'Other') ON CONFLICT DO NOTHING"
            )
            conn.execute(
                "INSERT INTO normalized_logs (log_id, raw_id, source_type, observer_hostname,"
                " timestamp, received_at, processed_at, severity, event_category, event_action,"
                " source_ip, destination_ip, message, tags, tenant_id)"
                " VALUES (%s,%s,'auth','host',%s,%s,%s,'high','auth','ssh_failure',"
                "'10.0.0.9','10.0.0.2','test','[]','other')",
                [str(uuid.uuid4()), str(uuid.uuid4()), ts, ts, ts],
            )

        rule = self._make_rule(is_corr=False)
        executor = SigmaExecutor.__new__(SigmaExecutor)
        with tmp_db._connect() as conn:
            results = executor.execute_backtest(
                rule, conn, "default",
                now - timedelta(hours=1), now,
            )
        assert all(r["group_value"] != "10.0.0.9" for r in results)


# ─── 3. Backtest route entegrasyon testleri ───────────────────────────────────


class TestBacktestRoute:
    def _headers(self, admin_token):
        return {"Authorization": f"Bearer {admin_token}"}

    def test_404_when_rule_not_found(self, sigma_dir, tmp_db, admin_token):
        r = client.post(
            "/api/v1/sigma/rules/nonexistent-uuid/backtest",
            json={"hours": 24},
            headers=self._headers(admin_token),
        )
        assert r.status_code == 404

    def test_401_when_no_auth(self, sigma_dir, tmp_db):
        r = client.post(
            f"/api/v1/sigma/rules/{_RULE_ID}/backtest",
            json={"hours": 24},
        )
        assert r.status_code == 401

    def test_valid_hours_returns_200_with_correct_shape(self, sigma_dir, tmp_db, admin_token):
        r = client.post(
            f"/api/v1/sigma/rules/{_RULE_ID}/backtest",
            json={"hours": 24},
            headers=self._headers(admin_token),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["rule_id"] == _RULE_ID
        assert "title" in data
        assert "severity" in data
        assert "is_correlation" in data
        assert "match_count" in data
        assert "matches" in data
        assert "duration_ms" in data
        assert data["window"]["hours"] == 24

    def test_valid_start_end_time(self, sigma_dir, tmp_db, admin_token):
        now = datetime.now(timezone.utc)
        r = client.post(
            f"/api/v1/sigma/rules/{_RULE_ID}/backtest",
            json={
                "start_time": (now - timedelta(hours=48)).isoformat(),
                "end_time":   now.isoformat(),
            },
            headers=self._headers(admin_token),
        )
        assert r.status_code == 200
        assert r.json()["window"]["hours"] is None

    def test_start_time_after_end_time_returns_422(self, sigma_dir, tmp_db, admin_token):
        now = datetime.now(timezone.utc)
        r = client.post(
            f"/api/v1/sigma/rules/{_RULE_ID}/backtest",
            json={
                "start_time": now.isoformat(),
                "end_time":   (now - timedelta(hours=1)).isoformat(),
            },
            headers=self._headers(admin_token),
        )
        assert r.status_code == 422

    def test_invalid_time_format_returns_422(self, sigma_dir, tmp_db, admin_token):
        r = client.post(
            f"/api/v1/sigma/rules/{_RULE_ID}/backtest",
            json={"start_time": "not-a-date", "end_time": "also-not"},
            headers=self._headers(admin_token),
        )
        assert r.status_code == 422

    def test_hours_zero_returns_422(self, sigma_dir, tmp_db, admin_token):
        r = client.post(
            f"/api/v1/sigma/rules/{_RULE_ID}/backtest",
            json={"hours": 0},
            headers=self._headers(admin_token),
        )
        assert r.status_code == 422

    def test_hours_169_returns_422(self, sigma_dir, tmp_db, admin_token):
        r = client.post(
            f"/api/v1/sigma/rules/{_RULE_ID}/backtest",
            json={"hours": 169},
            headers=self._headers(admin_token),
        )
        assert r.status_code == 422

    def test_disabled_rule_is_backtestable(self, sigma_dir, tmp_db, admin_token):
        yml = sigma_dir / f"{_RULE_ID}.yml"
        yml.rename(sigma_dir / f"{_RULE_ID}.yml.disabled")
        r = client.post(
            f"/api/v1/sigma/rules/{_RULE_ID}/backtest",
            json={"hours": 24},
            headers=self._headers(admin_token),
        )
        assert r.status_code == 200

    def test_match_count_reflects_actual_matches(self, sigma_dir, tmp_db, admin_token):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(minutes=30)).isoformat()
        with tmp_db._connect() as conn:
            for _ in range(5):
                conn.execute(
                    "INSERT INTO normalized_logs (log_id, raw_id, source_type, observer_hostname,"
                    " timestamp, received_at, processed_at, severity, event_category, event_action,"
                    " source_ip, destination_ip, message, tags, tenant_id)"
                    " VALUES (%s,%s,'auth','host',%s,%s,%s,'high','auth','ssh_failure',"
                    "'172.16.0.1','10.0.0.2','test','[]','default')",
                    [str(uuid.uuid4()), str(uuid.uuid4()), ts, ts, ts],
                )

        r = client.post(
            f"/api/v1/sigma/rules/{_RULE_ID}/backtest",
            json={"hours": 2},
            headers=self._headers(admin_token),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["match_count"] == len(data["matches"])

    def test_detection_rule_backtest(self, sigma_dir, tmp_db, admin_token):
        r = client.post(
            f"/api/v1/sigma/rules/{_DET_ID}/backtest",
            json={"hours": 24},
            headers=self._headers(admin_token),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["rule_id"] == _DET_ID
        assert data["is_correlation"] is False

    def test_matches_capped_at_100(self, sigma_dir, tmp_db, admin_token):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(minutes=30)).isoformat()
        ips = [f"192.168.{i // 256}.{i % 256}" for i in range(110)]
        with tmp_db._connect() as conn:
            for ip in ips:
                conn.execute(
                    "INSERT INTO normalized_logs (log_id, raw_id, source_type, observer_hostname,"
                    " timestamp, received_at, processed_at, severity, event_category, event_action,"
                    " source_ip, destination_ip, message, tags, tenant_id)"
                    " VALUES (%s,%s,'auth','host',%s,%s,%s,'high','auth','ssh_failure',"
                    f"'{ip}','10.0.0.2','test','[]','default')",
                    [str(uuid.uuid4()), str(uuid.uuid4()), ts, ts, ts],
                )

        r = client.post(
            f"/api/v1/sigma/rules/{_DET_ID}/backtest",
            json={"hours": 2},
            headers=self._headers(admin_token),
        )
        assert r.status_code == 200
        data = r.json()
        assert data["match_count"] >= 110
        assert len(data["matches"]) == 100
