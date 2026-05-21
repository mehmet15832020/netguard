"""
Analytics API — birim + entegrasyon testleri.
GET /api/v1/analytics/top-talkers
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from server.main import app

_client = TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
#  Fixture
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_db, admin_token):
    _client.headers.update({"Authorization": f"Bearer {admin_token}"})
    yield _client
    _client.headers.pop("Authorization", None)


@pytest.fixture
def superadmin_client(tmp_db, superadmin_token):
    _client.headers.update({"Authorization": f"Bearer {superadmin_token}"})
    yield _client
    _client.headers.pop("Authorization", None)


def _insert_log(
    tmp_db,
    source_ip="1.2.3.4",
    destination_ip="5.6.7.8",
    destination_port=None,
    minutes_ago=5,
    tenant_id="default",
):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    with tmp_db._connect() as conn:
        conn.execute(
            """
            INSERT INTO normalized_logs
              (log_id, raw_id, source_type, observer_hostname,
               timestamp, received_at, processed_at,
               severity, event_category, event_action,
               source_ip, destination_ip, destination_port,
               message, tags, tenant_id)
            VALUES (?, ?, 'test', 'test',
                    ?, ?, ?,
                    'info', 'network', 'connection',
                    ?, ?, ?,
                    'test', '[]', ?)
            """,
            (
                str(uuid.uuid4()), str(uuid.uuid4()),
                ts, ts, ts,
                source_ip, destination_ip, destination_port,
                tenant_id,
            ),
        )


# ─────────────────────────────────────────────────────────────────────────────
#  1. Temel yapı
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/top-talkers")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        resp = client.get("/api/v1/analytics/top-talkers")
        data = resp.json()
        assert "hours" in data
        assert "top_sources" in data
        assert "top_destinations" in data
        assert "top_dst_ports" in data

    def test_empty_db_returns_empty_lists(self, client):
        resp = client.get("/api/v1/analytics/top-talkers")
        data = resp.json()
        assert data["top_sources"] == []
        assert data["top_destinations"] == []
        assert data["top_dst_ports"] == []

    def test_default_hours_is_24(self, client):
        resp = client.get("/api/v1/analytics/top-talkers")
        assert resp.json()["hours"] == 24

    def test_hours_param_reflected_in_response(self, client):
        for h in [1, 6, 48, 168]:
            resp = client.get(f"/api/v1/analytics/top-talkers?hours={h}")
            assert resp.status_code == 200
            assert resp.json()["hours"] == h


# ─────────────────────────────────────────────────────────────────────────────
#  2. Doğrulama — geçersiz parametre
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersValidation:
    def test_hours_zero_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?hours=0")
        assert resp.status_code == 422

    def test_hours_169_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?hours=169")
        assert resp.status_code == 422

    def test_limit_zero_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?limit=0")
        assert resp.status_code == 422

    def test_limit_101_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?limit=101")
        assert resp.status_code == 422

    def test_hours_string_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?hours=DROP+TABLE")
        assert resp.status_code == 422

    def test_hours_overflow_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?hours=9999999999")
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
#  3. Kimlik doğrulama
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersAuth:
    def test_requires_auth_returns_401(self):
        c = TestClient(app)
        resp = c.get("/api/v1/analytics/top-talkers")
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
#  4. Multi-tenant izolasyon
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersTenantIsolation:
    def test_admin_sees_only_own_tenant(self, client, tmp_db, admin_token):
        _insert_log(tmp_db, source_ip="10.0.0.1", tenant_id="default")
        _insert_log(tmp_db, source_ip="10.0.0.2", tenant_id="other-tenant")

        resp = client.get("/api/v1/analytics/top-talkers")
        ips = [s["ip"] for s in resp.json()["top_sources"]]
        assert "10.0.0.1" in ips
        assert "10.0.0.2" not in ips

    def test_superadmin_sees_all_tenants(self, superadmin_client, tmp_db):
        _insert_log(tmp_db, source_ip="11.0.0.1", tenant_id="default")
        _insert_log(tmp_db, source_ip="11.0.0.2", tenant_id="other-tenant")

        resp = superadmin_client.get("/api/v1/analytics/top-talkers")
        ips = [s["ip"] for s in resp.json()["top_sources"]]
        assert "11.0.0.1" in ips
        assert "11.0.0.2" in ips


# ─────────────────────────────────────────────────────────────────────────────
#  5. Sıralama doğruluğu
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersOrdering:
    def test_top_sources_ordered_by_count_desc(self, client, tmp_db):
        for _ in range(5):
            _insert_log(tmp_db, source_ip="10.0.0.1")
        for _ in range(2):
            _insert_log(tmp_db, source_ip="10.0.0.2")
        _insert_log(tmp_db, source_ip="10.0.0.3")

        resp = client.get("/api/v1/analytics/top-talkers")
        sources = resp.json()["top_sources"]
        counts = [s["count"] for s in sources]
        assert counts == sorted(counts, reverse=True)
        assert sources[0]["ip"] == "10.0.0.1"
        assert sources[0]["count"] == 5

    def test_top_destinations_ordered_by_count_desc(self, client, tmp_db):
        for _ in range(4):
            _insert_log(tmp_db, destination_ip="8.8.8.8")
        for _ in range(2):
            _insert_log(tmp_db, destination_ip="1.1.1.1")

        resp = client.get("/api/v1/analytics/top-talkers")
        dests = resp.json()["top_destinations"]
        assert dests[0]["ip"] == "8.8.8.8"
        assert dests[0]["count"] == 4

    def test_top_dst_ports_ordered_by_count_desc(self, client, tmp_db):
        for _ in range(6):
            _insert_log(tmp_db, destination_port=443)
        for _ in range(3):
            _insert_log(tmp_db, destination_port=80)
        _insert_log(tmp_db, destination_port=22)

        resp = client.get("/api/v1/analytics/top-talkers")
        ports = resp.json()["top_dst_ports"]
        assert ports[0]["port"] == 443
        assert ports[0]["count"] == 6


# ─────────────────────────────────────────────────────────────────────────────
#  6. Limit parametresi
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersLimit:
    def test_limit_restricts_result_count(self, client, tmp_db):
        for i in range(10):
            _insert_log(tmp_db, source_ip=f"10.0.{i}.1")

        resp = client.get("/api/v1/analytics/top-talkers?limit=3")
        sources = resp.json()["top_sources"]
        assert len(sources) <= 3

    def test_limit_100_accepted(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?limit=100")
        assert resp.status_code == 200

    def test_limit_1_accepted(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="1.1.1.1")
        _insert_log(tmp_db, source_ip="2.2.2.2")

        resp = client.get("/api/v1/analytics/top-talkers?limit=1")
        assert resp.status_code == 200
        assert len(resp.json()["top_sources"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
#  7. Timestamp filtresi
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersTimestampFilter:
    def test_old_logs_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="9.9.9.9", minutes_ago=200)

        resp = client.get("/api/v1/analytics/top-talkers?hours=1")
        sources = resp.json()["top_sources"]
        assert not any(s["ip"] == "9.9.9.9" for s in sources)

    def test_recent_logs_included(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="7.7.7.7", minutes_ago=10)

        resp = client.get("/api/v1/analytics/top-talkers?hours=1")
        sources = resp.json()["top_sources"]
        assert any(s["ip"] == "7.7.7.7" for s in sources)

    def test_null_source_ip_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip=None)

        resp = client.get("/api/v1/analytics/top-talkers")
        sources = resp.json()["top_sources"]
        assert not any(s["ip"] is None for s in sources)

    def test_null_destination_port_excluded(self, client, tmp_db):
        _insert_log(tmp_db, destination_port=None)

        resp = client.get("/api/v1/analytics/top-talkers")
        ports = resp.json()["top_dst_ports"]
        assert not any(p["port"] is None for p in ports)

    def test_invalid_port_zero_excluded(self, client, tmp_db):
        _insert_log(tmp_db, destination_port=0)

        resp = client.get("/api/v1/analytics/top-talkers")
        ports = resp.json()["top_dst_ports"]
        assert not any(p["port"] == 0 for p in ports)

    def test_invalid_port_above_65535_excluded(self, client, tmp_db):
        _insert_log(tmp_db, destination_port=65536)

        resp = client.get("/api/v1/analytics/top-talkers")
        ports = resp.json()["top_dst_ports"]
        assert not any(p["port"] == 65536 for p in ports)
