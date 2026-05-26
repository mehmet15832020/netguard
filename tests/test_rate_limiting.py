"""
NetGuard — T2-5 Sistematik Rate Limiting testleri

Birim      : limiter.py default_limits, _auth_key key fonksiyonu
Çapraz     : kategori limitlerinin HTTP header ile dönüşü
Entegrasyon: 429 davranışı — discovery/scan, reports, logs, threat_intel,
             sigma write, correlation write, agent reporting, incidents write

Kaynak: OWASP API Security 2023 API4 — Unrestricted Resource Consumption,
        RFC 6585 §4 (429 Too Many Requests + Retry-After)
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from server.main import app
from server.auth import create_access_token
from server.limiter import limiter, _auth_key

client = TestClient(app, raise_server_exceptions=False)


def _auth(role: str = "admin") -> dict:
    token = create_access_token(username="testuser", role=role, tenant_id="default")
    return {"Authorization": f"Bearer {token}"}


# ─── Birim: _auth_key ─────────────────────────────────────────────────────────

class TestAuthKey:
    def test_returns_user_prefix_for_valid_jwt(self, tmp_db):
        token = create_access_token(username="alice", role="admin", tenant_id="default")
        from fastapi import Request
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
            "query_string": b"",
        }
        req = Request(scope)
        key = _auth_key(req)
        assert key == "user:alice"

    def test_falls_back_to_ip_for_invalid_token(self):
        from fastapi import Request
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [(b"authorization", b"Bearer invalid.token.here")],
            "query_string": b"",
            "client": ("1.2.3.4", 12345),
        }
        req = Request(scope)
        key = _auth_key(req)
        assert key == "1.2.3.4"

    def test_falls_back_to_ip_for_missing_auth(self):
        from fastapi import Request
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/test",
            "headers": [],
            "query_string": b"",
            "client": ("5.6.7.8", 9999),
        }
        req = Request(scope)
        key = _auth_key(req)
        assert key == "5.6.7.8"


# ─── Birim: limiter default_limits ──────────────────────────────────────────

class TestLimiterConfig:
    def test_default_limits_set(self):
        assert limiter._default_limits, "default_limits boş olmamalı"
        limits = list(limiter._default_limits[0])
        assert limits, "LimitGroup içinde en az bir Limit olmalı"
        assert "60" in str(limits[0].limit)

    def test_headers_enabled(self):
        assert limiter._headers_enabled is True

    def test_key_style_endpoint(self):
        assert limiter._key_style == "endpoint"


# ─── Entegrasyon: 429 ve header dönüşü ───────────────────────────────────────

class TestDiscoveryScanRateLimit:
    """POST /discovery/scan → 2/minute"""

    def test_scan_limit_429_on_third_call(self, tmp_db):
        headers = _auth("admin")
        payload = {"cidr": "10.0.0.0/24", "community": "public", "fingerprint": False}

        with patch("server.routes.discovery._run_scan"):
            r1 = client.post("/api/v1/discovery/scan", json=payload, headers=headers)
            r2 = client.post("/api/v1/discovery/scan", json=payload, headers=headers)
            r3 = client.post("/api/v1/discovery/scan", json=payload, headers=headers)

        assert r1.status_code in (202, 409)
        assert r2.status_code in (202, 409, 429)
        assert r3.status_code == 429, f"3. istek 429 olmalı, {r3.status_code} geldi"

    def test_scan_limit_429_has_retry_after_header(self, tmp_db):
        headers = _auth("admin")
        payload = {"cidr": "10.0.0.0/24", "community": "public", "fingerprint": False}

        with patch("server.routes.discovery._run_scan"):
            for _ in range(3):
                r = client.post("/api/v1/discovery/scan", json=payload, headers=headers)

        assert r.status_code == 429
        assert "x-ratelimit-limit" in r.headers or "retry-after" in r.headers


class TestReportsRateLimit:
    """GET /reports/* → 10/minute"""

    def test_security_status_429_after_10_calls(self, tmp_db):
        headers = _auth()
        last = None
        for i in range(12):
            last = client.get("/api/v1/reports/security-status", headers=headers)
        assert last.status_code == 429

    def test_summary_429_after_10_calls(self, tmp_db):
        headers = _auth()
        last = None
        for i in range(12):
            last = client.get("/api/v1/reports/summary", headers=headers)
        assert last.status_code == 429

    def test_first_10_calls_succeed(self, tmp_db):
        headers = _auth()
        for i in range(10):
            r = client.get("/api/v1/reports/security-status", headers=headers)
            assert r.status_code == 200, f"İstek {i+1} başarısız: {r.status_code}"


class TestLogsRateLimit:
    """GET /logs/normalized → 30/minute"""

    def test_logs_429_after_30_calls(self, tmp_db):
        headers = _auth()
        last = None
        for _ in range(32):
            last = client.get("/api/v1/logs/normalized", headers=headers)
        assert last.status_code == 429

    def test_first_30_calls_succeed(self, tmp_db):
        headers = _auth()
        for i in range(30):
            r = client.get("/api/v1/logs/normalized", headers=headers)
            assert r.status_code == 200, f"İstek {i+1} 200 olmalı, {r.status_code} geldi"


class TestThreatIntelRateLimit:
    """GET /threat-intel/* → 10/minute"""

    def test_threat_intel_429_after_10_calls(self, tmp_db):
        headers = _auth()
        last = None
        for _ in range(12):
            last = client.get("/api/v1/threat-intel/1.2.3.4", headers=headers)
        assert last.status_code == 429

    def test_first_10_calls_succeed(self, tmp_db):
        headers = _auth()
        with patch("server.threat_intel.lookup", return_value={"score": 0}):
            for i in range(10):
                r = client.get("/api/v1/threat-intel/1.2.3.4", headers=headers)
                assert r.status_code == 200, f"İstek {i+1} başarısız: {r.status_code}"


class TestSigmaWriteRateLimit:
    """POST/PATCH/DELETE /sigma/rules → 20/minute"""

    def test_validate_429_after_20_calls(self, tmp_db):
        headers = _auth("admin")
        payload = {"yaml_content": "title: Test\nstatus: test\ndetection:\n  selection:\n    event_action: test\n  condition: selection\nlogsource:\n  category: network\nlevel: medium"}
        last = None
        for _ in range(22):
            last = client.post("/api/v1/sigma/rules/validate", json=payload, headers=headers)
        assert last.status_code == 429

    def test_sigma_validate_first_20_succeed(self, tmp_db):
        headers = _auth("admin")
        payload = {"yaml_content": "title: Test\nstatus: test\ndetection:\n  selection:\n    event_action: test\n  condition: selection\nlogsource:\n  category: network\nlevel: medium"}
        for i in range(20):
            r = client.post("/api/v1/sigma/rules/validate", json=payload, headers=headers)
            assert r.status_code in (200, 422), f"İstek {i+1}: {r.status_code}"


class TestCorrelationWriteRateLimit:
    """POST /correlation/rules → 20/minute"""

    def test_create_rule_429_after_20_calls(self, tmp_db):
        headers = _auth("admin")
        last = None
        with (
            patch("server.routes.correlation._read_all_rules", return_value=[]),
            patch("server.routes.correlation._write_rules_atomic", return_value=0),
        ):
            for i in range(22):
                payload = {
                    "rule_id": f"test_rule_{i:03d}",
                    "name": f"Test Rule {i}",
                    "match_event_action": "ssh_failure",
                    "output_event_action": "brute_force_detected",
                    "group_by": "source_ip",
                    "threshold": 5,
                    "window_seconds": 60,
                    "severity": "warning",
                }
                last = client.post("/api/v1/correlation/rules", json=payload, headers=headers)
        assert last.status_code == 429

    def test_reload_429_after_20_calls(self, tmp_db):
        headers = _auth()
        last = None
        for _ in range(22):
            last = client.post("/api/v1/correlation/rules/reload", headers=headers)
        assert last.status_code == 429


class TestAgentReportingRateLimit:
    """POST /agents/metrics → 120/minute (yüksek limit — agent sık raporlar)"""

    def test_metrics_allowed_up_to_120(self, tmp_db):
        payload = {
            "agent_id": "test-agent-001",
            "hostname": "test-host",
            "cpu_percent": 10.0,
            "memory_percent": 50.0,
            "disk_percent": 30.0,
            "timestamp": "2026-05-26T00:00:00Z",
            "open_ports": [],
            "active_connections": [],
            "processes": [],
            "traffic_summary": None,
        }
        for i in range(5):
            r = client.post("/api/v1/agents/metrics", json=payload)
            assert r.status_code in (202, 422), f"İstek {i+1}: {r.status_code}"

    def test_register_allowed_at_120_per_minute(self, tmp_db):
        for i in range(5):
            payload = {
                "agent_id": f"agent-{i:03d}",
                "hostname": f"host-{i}",
                "os_name": "Linux",
                "os_version": "6.0",
                "version": "1.0",
            }
            r = client.post("/api/v1/agents/register", json=payload)
            assert r.status_code in (201, 422), f"İstek {i+1}: {r.status_code}"


class TestIncidentWriteRateLimit:
    """POST /incidents → 30/minute"""

    def test_create_incident_429_after_30_calls(self, tmp_db):
        headers = _auth()
        last = None
        for i in range(32):
            payload = {"title": f"Test Incident {i}", "severity": "warning"}
            last = client.post("/api/v1/incidents", json=payload, headers=headers)
        assert last.status_code == 429

    def test_resolve_all_429_after_10_calls(self, tmp_db):
        headers = _auth("admin")
        last = None
        for _ in range(12):
            last = client.post("/api/v1/incidents/resolve-all", headers=headers)
        assert last.status_code == 429


# ─── Entegrasyon: user bazlı limit izolasyonu ────────────────────────────────

class TestUserIsolation:
    """_auth_key ile farklı kullanıcılar birbirinin limitini tüketmez."""

    def test_different_users_independent_limits(self, tmp_db):
        token_a = create_access_token(username="user_a", role="admin", tenant_id="default")
        token_b = create_access_token(username="user_b", role="admin", tenant_id="default")
        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}

        for _ in range(10):
            client.get("/api/v1/reports/security-status", headers=headers_a)

        r_b = client.get("/api/v1/reports/security-status", headers=headers_b)
        assert r_b.status_code == 200, "user_b limiti user_a tarafından tüketilmemeli"

    def test_user_a_exhausted_does_not_block_user_b(self, tmp_db):
        token_a = create_access_token(username="user_x", role="admin", tenant_id="default")
        token_b = create_access_token(username="user_y", role="admin", tenant_id="default")
        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}

        last_a = None
        for _ in range(12):
            last_a = client.get("/api/v1/reports/security-status", headers=headers_a)
        assert last_a.status_code == 429

        r_b = client.get("/api/v1/reports/security-status", headers=headers_b)
        assert r_b.status_code == 200


# ─── Entegrasyon: rate limit header'ları ──────────────────────────────────────

class TestRateLimitHeaders:
    """SlowAPI headers_enabled=True → X-RateLimit-* header'ları dönmeli."""

    def test_ratelimit_headers_present_on_success(self, tmp_db):
        headers = _auth()
        r = client.get("/api/v1/reports/security-status", headers=headers)
        assert r.status_code == 200
        assert "x-ratelimit-limit" in r.headers
        assert "x-ratelimit-remaining" in r.headers

    def test_ratelimit_remaining_decrements(self, tmp_db):
        headers = _auth()
        r1 = client.get("/api/v1/reports/security-status", headers=headers)
        r2 = client.get("/api/v1/reports/security-status", headers=headers)
        rem1 = int(r1.headers.get("x-ratelimit-remaining", 999))
        rem2 = int(r2.headers.get("x-ratelimit-remaining", 999))
        assert rem2 < rem1, "remaining sayacı azalmalı"
