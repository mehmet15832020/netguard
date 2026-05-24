"""
Analytics API — birim + entegrasyon testleri.
GET /api/v1/analytics/top-talkers
GET /api/v1/analytics/alert-volume
GET /api/v1/analytics/protocol-distribution
GET /api/v1/analytics/traffic-volume
GET /api/v1/analytics/failed-auth
GET /api/v1/analytics/dns-analysis
GET /api/v1/analytics/tls-fingerprints
GET /api/v1/analytics/beaconing-summary
GET /api/v1/analytics/threat-summary
GET /api/v1/analytics/kill-chain-timeline
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
    received_at_minutes_ago=None,
    tenant_id="default",
    network_protocol=None,
    event_action="connection",
    tags="[]",
):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    ra = (datetime.now(timezone.utc) - timedelta(minutes=received_at_minutes_ago or minutes_ago)).isoformat()
    with tmp_db._connect() as conn:
        conn.execute(
            """
            INSERT INTO normalized_logs
              (log_id, raw_id, source_type, observer_hostname,
               timestamp, received_at, processed_at,
               severity, event_category, event_action,
               source_ip, destination_ip, destination_port,
               message, tags, tenant_id, network_protocol)
            VALUES (?, ?, 'test', 'test',
                    ?, ?, ?,
                    'info', 'network', ?,
                    ?, ?, ?,
                    'test', ?, ?, ?)
            """,
            (
                str(uuid.uuid4()), str(uuid.uuid4()),
                ts, ra, ra,
                event_action,
                source_ip, destination_ip, destination_port,
                tags, tenant_id, network_protocol,
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


# ─────────────────────────────────────────────────────────────────────────────
#  Alert Volume helpers
# ─────────────────────────────────────────────────────────────────────────────

def _insert_alert(
    tmp_db,
    severity="info",
    minutes_ago=5,
    tenant_id="default",
):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    with tmp_db._connect() as conn:
        conn.execute(
            """
            INSERT INTO alerts
              (alert_id, agent_id, hostname, severity, status,
               metric, message, value, threshold, triggered_at, tenant_id)
            VALUES (?, ?, 'test-host', ?, 'active',
                    'cpu', 'test', 80.0, 70.0, ?, ?)
            """,
            (str(uuid.uuid4()), str(uuid.uuid4()), severity, ts, tenant_id),
        )


# ─────────────────────────────────────────────────────────────────────────────
#  8. Alert Volume — temel yapı
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/alert-volume")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/alert-volume").json()
        assert "hours" in data
        assert "series" in data
        assert "bucket_minutes" in data
        for sev in ("critical", "high", "warning", "info"):
            assert sev in data["series"]

    def test_empty_db_returns_zero_counts(self, client):
        data = client.get("/api/v1/analytics/alert-volume").json()
        for sev in ("critical", "high", "warning", "info"):
            assert all(p["v"] == 0 for p in data["series"][sev])

    def test_default_hours_is_24(self, client):
        assert client.get("/api/v1/analytics/alert-volume").json()["hours"] == 24

    def test_hours_param_reflected(self, client):
        for h in [1, 6, 48, 168]:
            assert client.get(f"/api/v1/analytics/alert-volume?hours={h}").json()["hours"] == h


# ─────────────────────────────────────────────────────────────────────────────
#  8b. Alert Volume — adaptive granularity (bucket_minutes)
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeAdaptiveGranularity:
    def test_hours_1_returns_bucket_60(self, client):
        data = client.get("/api/v1/analytics/alert-volume?hours=1").json()
        assert data["bucket_minutes"] == 60

    def test_hours_6_returns_bucket_60(self, client):
        data = client.get("/api/v1/analytics/alert-volume?hours=6").json()
        assert data["bucket_minutes"] == 60

    def test_hours_7_returns_bucket_60(self, client):
        data = client.get("/api/v1/analytics/alert-volume?hours=7").json()
        assert data["bucket_minutes"] == 60

    def test_hours_24_returns_bucket_60(self, client):
        data = client.get("/api/v1/analytics/alert-volume?hours=24").json()
        assert data["bucket_minutes"] == 60

    def test_hours_25_returns_bucket_240(self, client):
        data = client.get("/api/v1/analytics/alert-volume?hours=25").json()
        assert data["bucket_minutes"] == 240

    def test_hours_168_returns_bucket_240(self, client):
        data = client.get("/api/v1/analytics/alert-volume?hours=168").json()
        assert data["bucket_minutes"] == 240


# ─────────────────────────────────────────────────────────────────────────────
#  9. Alert Volume — doğrulama
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeValidation:
    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/alert-volume?hours=0").status_code == 422

    def test_hours_169_returns_422(self, client):
        assert client.get("/api/v1/analytics/alert-volume?hours=169").status_code == 422

    def test_string_hours_returns_422(self, client):
        assert client.get("/api/v1/analytics/alert-volume?hours=abc").status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
#  10. Alert Volume — kimlik doğrulama
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeAuth:
    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/alert-volume").status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
#  11. Alert Volume — severity ayrımı
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeSeverity:
    def test_severity_separation(self, client, tmp_db):
        for sev in ("critical", "high", "warning", "info"):
            _insert_alert(tmp_db, severity=sev)

        data = client.get("/api/v1/analytics/alert-volume").json()
        for sev in ("critical", "high", "warning", "info"):
            assert sum(p["v"] for p in data["series"][sev]) == 1

    def test_all_series_same_length_when_data_exists(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical")
        _insert_alert(tmp_db, severity="high")

        data = client.get("/api/v1/analytics/alert-volume").json()
        lengths = [len(data["series"][s]) for s in ("critical", "high", "warning", "info")]
        assert len(set(lengths)) == 1

    def test_unknown_severity_excluded_from_series(self, client, tmp_db):
        ts = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        with tmp_db._connect() as conn:
            conn.execute(
                """INSERT INTO alerts
                     (alert_id, agent_id, hostname, severity, status,
                      metric, message, value, threshold, triggered_at, tenant_id)
                   VALUES (?, ?, 'host', 'unknown', 'active',
                           'cpu', 'test', 80, 70, ?, 'default')""",
                (str(uuid.uuid4()), str(uuid.uuid4()), ts),
            )

        data = client.get("/api/v1/analytics/alert-volume").json()
        assert "unknown" not in data["series"]

    def test_multiple_alerts_same_severity_aggregated(self, client, tmp_db):
        for _ in range(3):
            _insert_alert(tmp_db, severity="critical")

        data = client.get("/api/v1/analytics/alert-volume").json()
        assert sum(p["v"] for p in data["series"]["critical"]) == 3


# ─────────────────────────────────────────────────────────────────────────────
#  12. Alert Volume — timestamp filtresi
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeTimestamp:
    def test_old_alerts_excluded(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical", minutes_ago=200)

        data = client.get("/api/v1/analytics/alert-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["critical"]) == 0

    def test_recent_alerts_included(self, client, tmp_db):
        _insert_alert(tmp_db, severity="high", minutes_ago=10)

        data = client.get("/api/v1/analytics/alert-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["high"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
#  13. Alert Volume — sıralama
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeOrdering:
    def test_series_points_ordered_by_time_asc(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical", minutes_ago=120)
        _insert_alert(tmp_db, severity="critical", minutes_ago=60)
        _insert_alert(tmp_db, severity="critical", minutes_ago=5)

        data = client.get("/api/v1/analytics/alert-volume?hours=24").json()
        times = [p["t"] for p in data["series"]["critical"] if p["v"] > 0]
        assert times == sorted(times)


# ─────────────────────────────────────────────────────────────────────────────
#  14. Alert Volume — multi-tenant izolasyon
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeTenantIsolation:
    def test_admin_sees_only_own_tenant(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical", tenant_id="default")
        _insert_alert(tmp_db, severity="critical", tenant_id="other-tenant")

        data = client.get("/api/v1/analytics/alert-volume").json()
        assert sum(p["v"] for p in data["series"]["critical"]) == 1

    def test_superadmin_sees_all_tenants(self, superadmin_client, tmp_db):
        _insert_alert(tmp_db, severity="high", tenant_id="default")
        _insert_alert(tmp_db, severity="high", tenant_id="other-tenant")

        data = superadmin_client.get("/api/v1/analytics/alert-volume").json()
        assert sum(p["v"] for p in data["series"]["high"]) == 2

    def test_missing_where_clause_would_fail(self, client, tmp_db):
        _insert_alert(tmp_db, severity="warning", tenant_id="default")
        _insert_alert(tmp_db, severity="warning", tenant_id="other-tenant")
        _insert_alert(tmp_db, severity="warning", tenant_id="third-tenant")

        data = client.get("/api/v1/analytics/alert-volume").json()
        assert sum(p["v"] for p in data["series"]["warning"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
#  15. Alert Volume — zero-fill & bounds
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeZeroFill:
    def test_empty_db_returns_equal_length_series(self, client):
        data = client.get("/api/v1/analytics/alert-volume?hours=2").json()
        lengths = [len(data["series"][s]) for s in ("critical", "high", "warning", "info")]
        assert len(set(lengths)) == 1
        assert lengths[0] >= 2

    def test_sparse_data_still_aligned(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical", minutes_ago=90)

        data = client.get("/api/v1/analytics/alert-volume?hours=3").json()
        lengths = [len(data["series"][s]) for s in ("critical", "high", "warning", "info")]
        assert len(set(lengths)) == 1

    def test_future_triggered_at_excluded(self, client, tmp_db):
        future_ts = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        with tmp_db._connect() as conn:
            conn.execute(
                """INSERT INTO alerts
                     (alert_id, agent_id, hostname, severity, status,
                      metric, message, value, threshold, triggered_at, tenant_id)
                   VALUES (?, ?, 'host', 'critical', 'active',
                           'cpu', 'test', 80, 70, ?, 'default')""",
                (str(uuid.uuid4()), str(uuid.uuid4()), future_ts),
            )

        data = client.get("/api/v1/analytics/alert-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["critical"]) == 0


# ─────────────────────────────────────────────────────────────────────────────
#  Protocol Distribution tests
# ─────────────────────────────────────────────────────────────────────────────

class TestProtocolDistributionBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/protocol-distribution")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/protocol-distribution").json()
        assert "hours" in data
        assert "total" in data
        assert "protocols" in data

    def test_empty_db_returns_zero_total(self, client):
        data = client.get("/api/v1/analytics/protocol-distribution").json()
        assert data["total"] == 0
        assert data["protocols"] == []

    def test_default_hours_is_24(self, client):
        assert client.get("/api/v1/analytics/protocol-distribution").json()["hours"] == 24

    def test_hours_param_reflected(self, client):
        for h in [1, 6, 48, 168]:
            data = client.get(f"/api/v1/analytics/protocol-distribution?hours={h}").json()
            assert data["hours"] == h


class TestProtocolDistributionValidation:
    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/protocol-distribution?hours=0").status_code == 422

    def test_hours_169_returns_422(self, client):
        assert client.get("/api/v1/analytics/protocol-distribution?hours=169").status_code == 422

    def test_string_hours_returns_422(self, client):
        assert client.get("/api/v1/analytics/protocol-distribution?hours=x").status_code == 422


class TestProtocolDistributionAuth:
    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/protocol-distribution").status_code == 401


class TestProtocolDistributionData:
    def test_protocol_counted(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="tcp")
        _insert_log(tmp_db, network_protocol="tcp")
        _insert_log(tmp_db, network_protocol="udp")

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        protos = {p["protocol"]: p for p in data["protocols"]}
        assert protos["tcp"]["count"] == 2
        assert protos["udp"]["count"] == 1
        assert data["total"] == 3

    def test_pct_sums_to_100(self, client, tmp_db):
        for proto in ("tcp", "tcp", "udp", "icmp"):
            _insert_log(tmp_db, network_protocol=proto)

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        total_pct = sum(p["pct"] for p in data["protocols"])
        assert abs(total_pct - 100.0) < 0.5

    def test_ordered_by_count_desc(self, client, tmp_db):
        for _ in range(5):
            _insert_log(tmp_db, network_protocol="tcp")
        for _ in range(2):
            _insert_log(tmp_db, network_protocol="udp")
        _insert_log(tmp_db, network_protocol="icmp")

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        counts = [p["count"] for p in data["protocols"]]
        assert counts == sorted(counts, reverse=True)
        assert data["protocols"][0]["protocol"] == "tcp"

    def test_null_protocol_excluded(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol=None)

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        assert data["total"] == 0

    def test_empty_string_protocol_excluded(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="")

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        assert data["total"] == 0

    def test_protocol_lowercased(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="TCP")
        _insert_log(tmp_db, network_protocol="tcp")

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        protos = {p["protocol"] for p in data["protocols"]}
        assert "tcp" in protos
        assert "TCP" not in protos
        tcp_count = next(p["count"] for p in data["protocols"] if p["protocol"] == "tcp")
        assert tcp_count == 2

    def test_old_logs_excluded(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="tcp", minutes_ago=200)

        data = client.get("/api/v1/analytics/protocol-distribution?hours=1").json()
        assert data["total"] == 0

    def test_recent_logs_included(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="udp", minutes_ago=10)

        data = client.get("/api/v1/analytics/protocol-distribution?hours=1").json()
        assert data["total"] == 1


class TestProtocolDistributionTenantIsolation:
    def test_admin_sees_only_own_tenant(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="tcp", tenant_id="default")
        _insert_log(tmp_db, network_protocol="udp", tenant_id="other-tenant")

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        assert data["total"] == 1
        assert data["protocols"][0]["protocol"] == "tcp"

    def test_superadmin_sees_all_tenants(self, superadmin_client, tmp_db):
        _insert_log(tmp_db, network_protocol="tcp", tenant_id="default")
        _insert_log(tmp_db, network_protocol="udp", tenant_id="other-tenant")

        data = superadmin_client.get("/api/v1/analytics/protocol-distribution").json()
        assert data["total"] == 2


# ─────────────────────────────────────────────────────────────────────────────
#  Traffic Volume tests — 3-way East-West sınıflandırma
# ─────────────────────────────────────────────────────────────────────────────

class TestTrafficVolumeBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/traffic-volume")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert "hours" in data
        assert "series" in data
        assert "east_west" in data["series"]
        assert "ns_egress" in data["series"]
        assert "ns_ingress" in data["series"]

    def test_no_internal_or_external_keys(self, client):
        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert "internal" not in data["series"]
        assert "external" not in data["series"]

    def test_empty_db_returns_aligned_series(self, client):
        data = client.get("/api/v1/analytics/traffic-volume?hours=2").json()
        lengths = [len(data["series"][k]) for k in ("east_west", "ns_egress", "ns_ingress")]
        assert len(set(lengths)) == 1
        assert lengths[0] >= 2

    def test_default_hours_is_24(self, client):
        assert client.get("/api/v1/analytics/traffic-volume").json()["hours"] == 24

    def test_hours_param_reflected(self, client):
        for h in [1, 6, 48, 168]:
            data = client.get(f"/api/v1/analytics/traffic-volume?hours={h}").json()
            assert data["hours"] == h


class TestTrafficVolumeValidation:
    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/traffic-volume?hours=0").status_code == 422

    def test_hours_169_returns_422(self, client):
        assert client.get("/api/v1/analytics/traffic-volume?hours=169").status_code == 422

    def test_string_hours_returns_422(self, client):
        assert client.get("/api/v1/analytics/traffic-volume?hours=x").status_code == 422


class TestTrafficVolumeAuth:
    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/traffic-volume").status_code == 401


class TestTrafficVolumeDirection:
    def test_rfc1918_src_to_rfc1918_dst_is_east_west(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["east_west"]) == 1
        assert sum(p["v"] for p in data["series"]["ns_egress"]) == 0
        assert sum(p["v"] for p in data["series"]["ns_ingress"]) == 0

    def test_rfc1918_src_to_public_dst_is_ns_egress(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="8.8.8.8")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["ns_egress"]) == 1
        assert sum(p["v"] for p in data["series"]["east_west"]) == 0
        assert sum(p["v"] for p in data["series"]["ns_ingress"]) == 0

    def test_public_src_to_rfc1918_dst_is_ns_ingress(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="8.8.8.8", destination_ip="10.0.0.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["ns_ingress"]) == 1
        assert sum(p["v"] for p in data["series"]["east_west"]) == 0
        assert sum(p["v"] for p in data["series"]["ns_egress"]) == 0

    def test_both_public_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="8.8.8.8", destination_ip="1.1.1.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["east_west"]) == 0
        assert sum(p["v"] for p in data["series"]["ns_egress"]) == 0
        assert sum(p["v"] for p in data["series"]["ns_ingress"]) == 0

    def test_192168_src_to_172_dst_is_east_west(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="192.168.1.100", destination_ip="172.16.0.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["east_west"]) == 1

    def test_loopback_to_rfc1918_is_east_west(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="127.0.0.1", destination_ip="10.0.0.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["east_west"]) == 1

    def test_null_src_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip=None, destination_ip="10.0.0.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        total = sum(
            sum(p["v"] for p in data["series"][k])
            for k in ("east_west", "ns_egress", "ns_ingress")
        )
        assert total == 0

    def test_null_dst_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip=None)

        data = client.get("/api/v1/analytics/traffic-volume").json()
        total = sum(
            sum(p["v"] for p in data["series"][k])
            for k in ("east_west", "ns_egress", "ns_ingress")
        )
        assert total == 0

    def test_series_always_same_length(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1")
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="8.8.8.8")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        lengths = [len(data["series"][k]) for k in ("east_west", "ns_egress", "ns_ingress")]
        assert len(set(lengths)) == 1

    def test_mixed_traffic_correctly_classified(self, client, tmp_db):
        for _ in range(3):
            _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1")
        for _ in range(2):
            _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="8.8.8.8")
        _insert_log(tmp_db, source_ip="1.1.1.1", destination_ip="10.0.0.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["east_west"]) == 3
        assert sum(p["v"] for p in data["series"]["ns_egress"]) == 2
        assert sum(p["v"] for p in data["series"]["ns_ingress"]) == 1

    def test_172_16_to_172_31_range_is_rfc1918(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="172.31.255.254", destination_ip="172.16.0.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["east_west"]) == 1

    def test_172_above_31_is_public(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="172.32.0.1", destination_ip="10.0.0.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["ns_ingress"]) == 1
        assert sum(p["v"] for p in data["series"]["east_west"]) == 0


class TestTrafficVolumeTimestamp:
    def test_old_logs_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1", minutes_ago=200)

        data = client.get("/api/v1/analytics/traffic-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["east_west"]) == 0

    def test_recent_logs_included(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="8.8.8.8", destination_ip="10.0.0.1", minutes_ago=10)

        data = client.get("/api/v1/analytics/traffic-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["ns_ingress"]) == 1

    def test_received_at_determines_bucket_not_timestamp(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1",
                    minutes_ago=180, received_at_minutes_ago=5)

        data = client.get("/api/v1/analytics/traffic-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["east_west"]) == 1


class TestTrafficVolumeTenantIsolation:
    def test_admin_sees_only_own_tenant(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1", tenant_id="default")
        _insert_log(tmp_db, source_ip="10.0.0.2", destination_ip="192.168.1.2", tenant_id="other-tenant")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["east_west"]) == 1

    def test_superadmin_sees_all_tenants(self, superadmin_client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1", tenant_id="default")
        _insert_log(tmp_db, source_ip="10.0.0.2", destination_ip="192.168.1.2", tenant_id="other-tenant")

        data = superadmin_client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["east_west"]) == 2


# ─────────────────────────────────────────────────────────────────────────────
#  Failed Auth tests
# ─────────────────────────────────────────────────────────────────────────────

class TestFailedAuthBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/failed-auth")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/failed-auth").json()
        assert "hours" in data
        assert "total" in data
        assert "top_sources" in data
        assert "hourly" in data

    def test_empty_db_returns_zero_total(self, client):
        data = client.get("/api/v1/analytics/failed-auth").json()
        assert data["total"] == 0
        assert data["top_sources"] == []

    def test_default_hours_is_24(self, client):
        assert client.get("/api/v1/analytics/failed-auth").json()["hours"] == 24

    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/failed-auth").status_code == 401

    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/failed-auth?hours=0").status_code == 422

    def test_hours_169_returns_422(self, client):
        assert client.get("/api/v1/analytics/failed-auth?hours=169").status_code == 422


class TestFailedAuthData:
    def test_ssh_failure_counted(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="1.2.3.4", event_action="ssh_failure")
        _insert_log(tmp_db, source_ip="1.2.3.4", event_action="ssh_failure")

        data = client.get("/api/v1/analytics/failed-auth").json()
        assert data["total"] == 2
        assert data["top_sources"][0]["ip"] == "1.2.3.4"
        assert data["top_sources"][0]["count"] == 2

    def test_brute_force_detected_counted(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="5.5.5.5", event_action="brute_force_detected")

        data = client.get("/api/v1/analytics/failed-auth").json()
        assert data["total"] == 1

    def test_windows_logon_failure_counted(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="6.6.6.6", event_action="windows_logon_failure")

        data = client.get("/api/v1/analytics/failed-auth").json()
        assert data["total"] == 1

    def test_authentication_failed_counted(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="7.7.7.7", event_action="authentication_failed")

        data = client.get("/api/v1/analytics/failed-auth").json()
        assert data["total"] == 1

    def test_unrelated_event_not_counted(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="8.8.8.8", event_action="connection")

        data = client.get("/api/v1/analytics/failed-auth").json()
        assert data["total"] == 0

    def test_top_sources_ordered_by_count_desc(self, client, tmp_db):
        for _ in range(5):
            _insert_log(tmp_db, source_ip="10.0.0.1", event_action="ssh_failure")
        for _ in range(2):
            _insert_log(tmp_db, source_ip="10.0.0.2", event_action="ssh_failure")

        data = client.get("/api/v1/analytics/failed-auth").json()
        assert data["top_sources"][0]["ip"] == "10.0.0.1"
        assert data["top_sources"][0]["count"] == 5

    def test_hourly_zero_filled(self, client):
        data = client.get("/api/v1/analytics/failed-auth?hours=3").json()
        assert len(data["hourly"]) >= 3

    def test_old_logs_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="1.2.3.4", event_action="ssh_failure", minutes_ago=200)

        data = client.get("/api/v1/analytics/failed-auth?hours=1").json()
        assert data["total"] == 0

    def test_tenant_isolation(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="1.2.3.4", event_action="ssh_failure", tenant_id="default")
        _insert_log(tmp_db, source_ip="5.6.7.8", event_action="ssh_failure", tenant_id="other")

        data = client.get("/api/v1/analytics/failed-auth").json()
        assert data["total"] == 1


# ─────────────────────────────────────────────────────────────────────────────
#  DNS Analysis tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDnsAnalysisBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/dns-analysis")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/dns-analysis").json()
        assert "hours" in data
        assert "top_queried_destinations" in data
        assert "nxdomain_count" in data
        assert "nxdomain_rate" in data
        assert "hourly_volume" in data
        assert "unique_destinations" in data

    def test_empty_db_returns_zeros(self, client):
        data = client.get("/api/v1/analytics/dns-analysis").json()
        assert data["nxdomain_count"] == 0
        assert data["nxdomain_rate"] == 0.0
        assert data["unique_destinations"] == 0

    def test_default_hours_is_24(self, client):
        assert client.get("/api/v1/analytics/dns-analysis").json()["hours"] == 24

    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/dns-analysis").status_code == 401

    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/dns-analysis?hours=0").status_code == 422

    def test_limit_101_returns_422(self, client):
        assert client.get("/api/v1/analytics/dns-analysis?limit=101").status_code == 422


class TestDnsAnalysisData:
    def test_dns_query_events_counted(self, client, tmp_db):
        _insert_log(tmp_db, event_action="dns_query", destination_ip="8.8.8.8")
        _insert_log(tmp_db, event_action="dns_query", destination_ip="8.8.8.8")
        _insert_log(tmp_db, event_action="dns_query", destination_ip="1.1.1.1")

        data = client.get("/api/v1/analytics/dns-analysis").json()
        assert data["unique_destinations"] == 2

    def test_non_dns_events_excluded(self, client, tmp_db):
        _insert_log(tmp_db, event_action="connection", destination_ip="8.8.8.8")

        data = client.get("/api/v1/analytics/dns-analysis").json()
        assert data["unique_destinations"] == 0

    def test_hourly_volume_zero_filled(self, client):
        data = client.get("/api/v1/analytics/dns-analysis?hours=3").json()
        assert len(data["hourly_volume"]) >= 3

    def test_tenant_isolation(self, client, tmp_db):
        _insert_log(tmp_db, event_action="dns_query", destination_ip="8.8.8.8", tenant_id="default")
        _insert_log(tmp_db, event_action="dns_query", destination_ip="1.1.1.1", tenant_id="other")

        data = client.get("/api/v1/analytics/dns-analysis").json()
        assert data["unique_destinations"] == 1

    def test_new_fields_present_in_response(self, client):
        data = client.get("/api/v1/analytics/dns-analysis").json()
        assert "high_entropy_count" in data
        assert "long_query_count" in data
        assert "anomaly_count" in data

    def test_high_entropy_counted(self, client, tmp_db):
        _insert_log(tmp_db, event_action="dns_query", destination_ip="8.8.8.8",
                    tags='["dns_query"]')
        # Simulate high entropy message
        with tmp_db._connect() as conn:
            conn.execute(
                """
                UPDATE normalized_logs SET message = 'DNS sorgusu: [HIGH_ENTROPY:5.2] abc.example.com'
                WHERE event_action = 'dns_query'
                """
            )
        data = client.get("/api/v1/analytics/dns-analysis").json()
        assert data["high_entropy_count"] == 1

    def test_long_query_counted(self, client, tmp_db):
        _insert_log(tmp_db, event_action="dns_query", destination_ip="8.8.8.8")
        with tmp_db._connect() as conn:
            conn.execute(
                """
                UPDATE normalized_logs SET message = 'DNS sorgusu: [LONG_QUERY:65] verylongsubdomain.example.com'
                WHERE event_action = 'dns_query'
                """
            )
        data = client.get("/api/v1/analytics/dns-analysis").json()
        assert data["long_query_count"] == 1

    def test_anomaly_burst_counted(self, client, tmp_db):
        _insert_log(tmp_db, event_action="dns_query_burst", destination_ip="8.8.8.8")
        data = client.get("/api/v1/analytics/dns-analysis").json()
        assert data["anomaly_count"] == 1

    def test_empty_new_fields_are_zero(self, client):
        data = client.get("/api/v1/analytics/dns-analysis").json()
        assert data["high_entropy_count"] == 0
        assert data["long_query_count"] == 0
        assert data["anomaly_count"] == 0

    def test_nxdomain_rate_is_percentage(self, client, tmp_db):
        for _ in range(3):
            _insert_log(tmp_db, event_action="dns_query", destination_ip="8.8.8.8")
        with tmp_db._connect() as conn:
            conn.execute(
                "UPDATE normalized_logs SET message = 'NXDOMAIN notfound.example.com'"
            )
        data = client.get("/api/v1/analytics/dns-analysis").json()
        assert 0 <= data["nxdomain_rate"] <= 100


# ─────────────────────────────────────────────────────────────────────────────
#  TLS Fingerprints tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTlsFingerprintsBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/tls-fingerprints")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/tls-fingerprints").json()
        assert "hours" in data
        assert "top_fingerprints" in data
        assert "unique_count" in data

    def test_empty_db_returns_zero(self, client):
        data = client.get("/api/v1/analytics/tls-fingerprints").json()
        assert data["unique_count"] == 0
        assert data["top_fingerprints"] == []

    def test_default_hours_is_24(self, client):
        assert client.get("/api/v1/analytics/tls-fingerprints").json()["hours"] == 24

    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/tls-fingerprints").status_code == 401

    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/tls-fingerprints?hours=0").status_code == 422

    def test_limit_101_returns_422(self, client):
        assert client.get("/api/v1/analytics/tls-fingerprints?limit=101").status_code == 422

    def test_tenant_isolation(self, client, tmp_db):
        _insert_log(tmp_db, event_action="tls_connection", tenant_id="default")
        _insert_log(tmp_db, event_action="tls_connection", tenant_id="other")

        data = client.get("/api/v1/analytics/tls-fingerprints").json()
        assert data["unique_count"] <= 1


# ─────────────────────────────────────────────────────────────────────────────
#  Beaconing Summary tests
# ─────────────────────────────────────────────────────────────────────────────

class TestBeaconingSummaryBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/beaconing-summary")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/beaconing-summary").json()
        assert "hours" in data
        assert "detections" in data
        assert "total" in data

    def test_empty_db_returns_zero(self, client):
        data = client.get("/api/v1/analytics/beaconing-summary").json()
        assert data["total"] == 0
        assert data["detections"] == []

    def test_default_hours_is_24(self, client):
        assert client.get("/api/v1/analytics/beaconing-summary").json()["hours"] == 24

    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/beaconing-summary").status_code == 401

    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/beaconing-summary?hours=0").status_code == 422

    def test_hours_169_returns_422(self, client):
        assert client.get("/api/v1/analytics/beaconing-summary?hours=169").status_code == 422


class TestBeaconingSummaryData:
    def test_c2_beaconing_events_counted(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.5", destination_ip="1.2.3.4",
                    event_action="c2_beaconing")
        _insert_log(tmp_db, source_ip="10.0.0.5", destination_ip="1.2.3.4",
                    event_action="c2_beaconing")

        data = client.get("/api/v1/analytics/beaconing-summary").json()
        assert data["total"] == 2

    def test_non_beaconing_events_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.5", event_action="connection")

        data = client.get("/api/v1/analytics/beaconing-summary").json()
        assert data["total"] == 0

    def test_detection_has_required_fields(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.5", destination_ip="1.2.3.4",
                    event_action="c2_beaconing")

        data = client.get("/api/v1/analytics/beaconing-summary").json()
        assert data["total"] == 1
        det = data["detections"][0]
        assert "source_ip" in det
        assert "destination_ip" in det
        assert "message" in det
        assert "detected_at" in det

    def test_old_events_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.5", event_action="c2_beaconing", minutes_ago=200)

        data = client.get("/api/v1/analytics/beaconing-summary?hours=1").json()
        assert data["total"] == 0

    def test_tenant_isolation(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", event_action="c2_beaconing", tenant_id="default")
        _insert_log(tmp_db, source_ip="10.0.0.2", event_action="c2_beaconing", tenant_id="other")

        data = client.get("/api/v1/analytics/beaconing-summary").json()
        assert data["total"] == 1


# ─────────────────────────────────────────────────────────────────────────────
#  Threat Summary tests
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatSummaryBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/threat-summary")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/threat-summary").json()
        assert "hours" in data
        assert "top_sources" in data
        assert "total_alerts" in data
        assert "critical_count" in data

    def test_empty_db_returns_zeros(self, client):
        data = client.get("/api/v1/analytics/threat-summary").json()
        assert data["total_alerts"] == 0
        assert data["critical_count"] == 0
        assert data["top_sources"] == []

    def test_default_hours_is_24(self, client):
        assert client.get("/api/v1/analytics/threat-summary").json()["hours"] == 24

    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/threat-summary").status_code == 401

    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/threat-summary?hours=0").status_code == 422

    def test_hours_169_returns_422(self, client):
        assert client.get("/api/v1/analytics/threat-summary?hours=169").status_code == 422

    def test_limit_101_returns_422(self, client):
        assert client.get("/api/v1/analytics/threat-summary?limit=101").status_code == 422


class TestThreatSummaryData:
    def test_total_alerts_counts_all_severities(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical")
        _insert_alert(tmp_db, severity="high")
        _insert_alert(tmp_db, severity="info")

        data = client.get("/api/v1/analytics/threat-summary").json()
        assert data["total_alerts"] == 3

    def test_critical_count_counts_only_critical(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical")
        _insert_alert(tmp_db, severity="critical")
        _insert_alert(tmp_db, severity="high")

        data = client.get("/api/v1/analytics/threat-summary").json()
        assert data["critical_count"] == 2

    def test_threat_intel_sources_counted(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="1.2.3.4", tags='["threat_intel"]')

        data = client.get("/api/v1/analytics/threat-summary").json()
        assert data["top_sources"][0]["ip"] == "1.2.3.4"

    def test_non_threat_intel_sources_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="9.9.9.9", tags='[]')

        data = client.get("/api/v1/analytics/threat-summary").json()
        assert not any(s["ip"] == "9.9.9.9" for s in data["top_sources"])

    def test_old_alerts_excluded(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical", minutes_ago=200)

        data = client.get("/api/v1/analytics/threat-summary?hours=1").json()
        assert data["total_alerts"] == 0

    def test_tenant_isolation_alerts(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical", tenant_id="default")
        _insert_alert(tmp_db, severity="critical", tenant_id="other")

        data = client.get("/api/v1/analytics/threat-summary").json()
        assert data["critical_count"] == 1


def _insert_threat_intel_cache(tmp_db, ip, composite_score=0, country_code="", isp=""):
    with tmp_db._connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO threat_intel_cache
              (ip, score, total_reports, country_code, isp,
               feodo_listed, threatfox_score, greynoise_noise, greynoise_riot,
               composite_score, queried_at)
            VALUES (?, 0, 0, ?, ?, 0, 0, 0, 0, ?, datetime('now'))
            """,
            (ip, country_code or None, isp or None, composite_score),
        )


class TestThreatSummaryNewFields:
    def test_response_has_new_fields(self, client):
        data = client.get("/api/v1/analytics/threat-summary").json()
        assert "high_risk_count" in data
        assert "country_distribution" in data

    def test_top_source_has_extended_fields(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="1.2.3.4", tags='["threat_intel"]')

        data = client.get("/api/v1/analytics/threat-summary").json()
        src = data["top_sources"][0]
        assert "last_seen" in src
        assert "composite_score" in src
        assert "country_code" in src
        assert "isp" in src

    def test_high_risk_count_zero_when_no_high_score_ips(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="1.2.3.4", tags='["threat_intel"]')
        _insert_threat_intel_cache(tmp_db, ip="1.2.3.4", composite_score=50)

        data = client.get("/api/v1/analytics/threat-summary").json()
        assert data["high_risk_count"] == 0

    def test_high_risk_count_includes_score_70_and_above(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", tags='["threat_intel"]')
        _insert_log(tmp_db, source_ip="10.0.0.2", tags='["threat_intel"]')
        _insert_log(tmp_db, source_ip="10.0.0.3", tags='["threat_intel"]')
        _insert_threat_intel_cache(tmp_db, ip="10.0.0.1", composite_score=70)
        _insert_threat_intel_cache(tmp_db, ip="10.0.0.2", composite_score=100)
        _insert_threat_intel_cache(tmp_db, ip="10.0.0.3", composite_score=69)

        data = client.get("/api/v1/analytics/threat-summary").json()
        assert data["high_risk_count"] == 2

    def test_high_risk_count_excludes_no_cache_entry(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="5.5.5.5", tags='["threat_intel"]')

        data = client.get("/api/v1/analytics/threat-summary").json()
        assert data["high_risk_count"] == 0

    def test_composite_score_populated_from_cache(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="2.2.2.2", tags='["threat_intel"]')
        _insert_threat_intel_cache(tmp_db, ip="2.2.2.2", composite_score=85)

        data = client.get("/api/v1/analytics/threat-summary").json()
        src = next(s for s in data["top_sources"] if s["ip"] == "2.2.2.2")
        assert src["composite_score"] == 85

    def test_composite_score_zero_when_no_cache(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="3.3.3.3", tags='["threat_intel"]')

        data = client.get("/api/v1/analytics/threat-summary").json()
        src = next(s for s in data["top_sources"] if s["ip"] == "3.3.3.3")
        assert src["composite_score"] == 0

    def test_country_code_populated_from_cache(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="4.4.4.4", tags='["threat_intel"]')
        _insert_threat_intel_cache(tmp_db, ip="4.4.4.4", country_code="RU")

        data = client.get("/api/v1/analytics/threat-summary").json()
        src = next(s for s in data["top_sources"] if s["ip"] == "4.4.4.4")
        assert src["country_code"] == "RU"

    def test_country_code_empty_when_no_cache(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="5.5.5.5", tags='["threat_intel"]')

        data = client.get("/api/v1/analytics/threat-summary").json()
        src = next(s for s in data["top_sources"] if s["ip"] == "5.5.5.5")
        assert src["country_code"] == ""

    def test_isp_populated_from_cache(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="6.6.6.6", tags='["threat_intel"]')
        _insert_threat_intel_cache(tmp_db, ip="6.6.6.6", isp="Shady ISP Ltd")

        data = client.get("/api/v1/analytics/threat-summary").json()
        src = next(s for s in data["top_sources"] if s["ip"] == "6.6.6.6")
        assert src["isp"] == "Shady ISP Ltd"

    def test_last_seen_is_string(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="7.7.7.7", tags='["threat_intel"]')

        data = client.get("/api/v1/analytics/threat-summary").json()
        src = next(s for s in data["top_sources"] if s["ip"] == "7.7.7.7")
        assert isinstance(src["last_seen"], str)
        assert len(src["last_seen"]) > 0

    def test_country_distribution_empty_when_no_data(self, client):
        data = client.get("/api/v1/analytics/threat-summary").json()
        assert data["country_distribution"] == []

    def test_country_distribution_grouped_by_country(self, client, tmp_db):
        for ip in ("10.0.1.1", "10.0.1.2"):
            _insert_log(tmp_db, source_ip=ip, tags='["threat_intel"]')
            _insert_threat_intel_cache(tmp_db, ip=ip, country_code="CN")
        _insert_log(tmp_db, source_ip="10.0.1.3", tags='["threat_intel"]')
        _insert_threat_intel_cache(tmp_db, ip="10.0.1.3", country_code="RU")

        data = client.get("/api/v1/analytics/threat-summary").json()
        dist = {d["country_code"]: d["ip_count"] for d in data["country_distribution"]}
        assert dist["CN"] == 2
        assert dist["RU"] == 1

    def test_country_distribution_unknown_becomes_xx(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="11.0.0.1", tags='["threat_intel"]')

        data = client.get("/api/v1/analytics/threat-summary").json()
        dist = {d["country_code"]: d["ip_count"] for d in data["country_distribution"]}
        assert "XX" in dist

    def test_country_distribution_ordered_by_ip_count_desc(self, client, tmp_db):
        for i, (cc, count) in enumerate([("US", 3), ("CN", 5), ("RU", 1)]):
            for j in range(count):
                ip = f"20.{i}.0.{j + 1}"
                _insert_log(tmp_db, source_ip=ip, tags='["threat_intel"]')
                _insert_threat_intel_cache(tmp_db, ip=ip, country_code=cc)

        data = client.get("/api/v1/analytics/threat-summary").json()
        counts = [d["ip_count"] for d in data["country_distribution"]]
        assert counts == sorted(counts, reverse=True)

    def test_top_sources_ordered_by_composite_score_desc(self, client, tmp_db):
        for ip, score in [("30.0.0.1", 20), ("30.0.0.2", 90), ("30.0.0.3", 60)]:
            _insert_log(tmp_db, source_ip=ip, tags='["threat_intel"]')
            _insert_threat_intel_cache(tmp_db, ip=ip, composite_score=score)

        data = client.get("/api/v1/analytics/threat-summary").json()
        scores = [s["composite_score"] for s in data["top_sources"]]
        assert scores == sorted(scores, reverse=True)

    def test_tenant_isolation_high_risk_count(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="40.0.0.1", tags='["threat_intel"]', tenant_id="default")
        _insert_log(tmp_db, source_ip="40.0.0.2", tags='["threat_intel"]', tenant_id="other")
        _insert_threat_intel_cache(tmp_db, ip="40.0.0.1", composite_score=80)
        _insert_threat_intel_cache(tmp_db, ip="40.0.0.2", composite_score=80)

        data = client.get("/api/v1/analytics/threat-summary").json()
        assert data["high_risk_count"] == 1

    def test_tenant_isolation_country_distribution(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="50.0.0.1", tags='["threat_intel"]', tenant_id="default")
        _insert_log(tmp_db, source_ip="50.0.0.2", tags='["threat_intel"]', tenant_id="other")
        _insert_threat_intel_cache(tmp_db, ip="50.0.0.1", country_code="DE")
        _insert_threat_intel_cache(tmp_db, ip="50.0.0.2", country_code="FR")

        data = client.get("/api/v1/analytics/threat-summary").json()
        codes = {d["country_code"] for d in data["country_distribution"]}
        assert "DE" in codes
        assert "FR" not in codes


# ─────────────────────────────────────────────────────────────────────────────
#  Kill Chain Timeline
# ─────────────────────────────────────────────────────────────────────────────

def _insert_chain_stage(tmp_db, source_ip="1.2.3.4", stage="recon", minutes_ago=5, tenant_id="default"):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    with tmp_db._connect() as conn:
        conn.execute(
            "INSERT INTO attack_chain_state (source_ip, stage, occurred_at, tenant_id) VALUES (?, ?, ?, ?)",
            (source_ip, stage, ts, tenant_id),
        )


class TestKillChainTimelineBasic:
    def test_returns_200(self, client):
        resp = client.get("/api/v1/analytics/kill-chain-timeline")
        assert resp.status_code == 200

    def test_response_schema(self, client):
        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        assert "hours" in data
        assert "window_start" in data
        assert "window_end" in data
        assert "rows" in data
        assert data["hours"] == 24

    def test_empty_returns_empty_rows(self, client):
        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        assert data["rows"] == []

    def test_hours_reflected(self, client):
        for h in [6, 48, 168]:
            data = client.get(f"/api/v1/analytics/kill-chain-timeline?hours={h}").json()
            assert data["hours"] == h


class TestKillChainTimelineData:
    def test_single_stage_event_returned(self, client, tmp_db):
        _insert_chain_stage(tmp_db, source_ip="10.0.0.1", stage="recon")
        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        assert len(data["rows"]) == 1
        row = data["rows"][0]
        assert row["source_ip"] == "10.0.0.1"
        assert len(row["events"]) == 1
        assert row["events"][0]["stage"] == "recon"

    def test_event_has_required_fields(self, client, tmp_db):
        _insert_chain_stage(tmp_db, source_ip="10.0.0.2", stage="weaponize")
        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        ev = data["rows"][0]["events"][0]
        assert "stage" in ev
        assert "label" in ev
        assert "occurred_at" in ev

    def test_stage_label_populated(self, client, tmp_db):
        for stage, expected_label in [
            ("recon", "Keşif"),
            ("weaponize", "Silahlanma"),
            ("access", "Erişim"),
            ("lateral", "Yanal Hareket"),
        ]:
            _insert_chain_stage(tmp_db, source_ip=f"10.0.1.{STAGE_ORDER_MAP[stage]}", stage=stage)

        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        label_map = {r["events"][0]["stage"]: r["events"][0]["label"] for r in data["rows"]}
        assert label_map["recon"] == "Keşif"
        assert label_map["weaponize"] == "Silahlanma"
        assert label_map["access"] == "Erişim"
        assert label_map["lateral"] == "Yanal Hareket"

    def test_full_chain_type_for_3_stages(self, client, tmp_db):
        for stage in ["recon", "weaponize", "access"]:
            _insert_chain_stage(tmp_db, source_ip="10.0.0.3", stage=stage)
        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        row = next(r for r in data["rows"] if r["source_ip"] == "10.0.0.3")
        assert row["chain_type"] == "FULL_ATTACK_CHAIN"
        assert row["stage_count"] == 3

    def test_partial_chain_type_for_2_stages(self, client, tmp_db):
        for stage in ["recon", "weaponize"]:
            _insert_chain_stage(tmp_db, source_ip="10.0.0.4", stage=stage)
        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        row = next(r for r in data["rows"] if r["source_ip"] == "10.0.0.4")
        assert row["chain_type"] == "PARTIAL_ATTACK_CHAIN"
        assert row["stage_count"] == 2

    def test_rows_sorted_by_stage_count_desc(self, client, tmp_db):
        _insert_chain_stage(tmp_db, source_ip="10.1.1.1", stage="recon")
        for stage in ["recon", "weaponize", "access"]:
            _insert_chain_stage(tmp_db, source_ip="10.1.1.2", stage=stage)
        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        stage_counts = [r["stage_count"] for r in data["rows"]]
        assert stage_counts == sorted(stage_counts, reverse=True)

    def test_old_events_excluded(self, client, tmp_db):
        _insert_chain_stage(tmp_db, source_ip="10.0.0.5", stage="recon", minutes_ago=200)
        data = client.get("/api/v1/analytics/kill-chain-timeline?hours=1").json()
        assert all(r["source_ip"] != "10.0.0.5" for r in data["rows"])

    def test_first_seen_last_seen_order(self, client, tmp_db):
        _insert_chain_stage(tmp_db, source_ip="10.0.0.6", stage="recon",     minutes_ago=20)
        _insert_chain_stage(tmp_db, source_ip="10.0.0.6", stage="weaponize", minutes_ago=10)
        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        row = next(r for r in data["rows"] if r["source_ip"] == "10.0.0.6")
        assert row["first_seen"] < row["last_seen"]

    def test_multiple_ips_returned(self, client, tmp_db):
        for ip in ["10.2.1.1", "10.2.1.2", "10.2.1.3"]:
            _insert_chain_stage(tmp_db, source_ip=ip, stage="recon")
        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        ips = {r["source_ip"] for r in data["rows"]}
        assert {"10.2.1.1", "10.2.1.2", "10.2.1.3"}.issubset(ips)

    def test_limit_respected(self, client, tmp_db):
        for i in range(10):
            _insert_chain_stage(tmp_db, source_ip=f"10.3.0.{i + 1}", stage="recon")
        data = client.get("/api/v1/analytics/kill-chain-timeline?limit=3").json()
        assert len(data["rows"]) <= 3

    def test_window_start_end_present(self, client, tmp_db):
        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        assert data["window_start"] < data["window_end"]


class TestKillChainTimelineTenantIsolation:
    def test_tenant_sees_only_own_data(self, client, tmp_db):
        _insert_chain_stage(tmp_db, source_ip="10.9.9.1", stage="recon", tenant_id="default")
        _insert_chain_stage(tmp_db, source_ip="10.9.9.2", stage="recon", tenant_id="other")
        data = client.get("/api/v1/analytics/kill-chain-timeline").json()
        ips = {r["source_ip"] for r in data["rows"]}
        assert "10.9.9.1" in ips
        assert "10.9.9.2" not in ips

    def test_superadmin_sees_all_tenants(self, superadmin_client, tmp_db):
        _insert_chain_stage(tmp_db, source_ip="10.9.9.3", stage="recon", tenant_id="default")
        _insert_chain_stage(tmp_db, source_ip="10.9.9.4", stage="recon", tenant_id="other")
        data = superadmin_client.get("/api/v1/analytics/kill-chain-timeline").json()
        ips = {r["source_ip"] for r in data["rows"]}
        assert "10.9.9.3" in ips
        assert "10.9.9.4" in ips


STAGE_ORDER_MAP = {"recon": 1, "weaponize": 2, "access": 3, "lateral": 4}


# ─────────────────────────────────────────────────────────────────────────────
#  East-West Connection Matrix
# ─────────────────────────────────────────────────────────────────────────────

class TestEastWestMatrixBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/east-west-matrix")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/east-west-matrix").json()
        assert "hours" in data
        assert "rows" in data
        assert "max_count" in data
        assert "unique_pairs" in data

    def test_empty_db_returns_empty_rows(self, client):
        data = client.get("/api/v1/analytics/east-west-matrix").json()
        assert data["rows"] == []
        assert data["max_count"] == 0

    def test_default_hours_is_24(self, client):
        data = client.get("/api/v1/analytics/east-west-matrix").json()
        assert data["hours"] == 24

    def test_hours_param_reflected(self, client):
        data = client.get("/api/v1/analytics/east-west-matrix?hours=48").json()
        assert data["hours"] == 48


class TestEastWestMatrixValidation:
    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/east-west-matrix?hours=0").status_code == 422

    def test_hours_169_returns_422(self, client):
        assert client.get("/api/v1/analytics/east-west-matrix?hours=169").status_code == 422

    def test_limit_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/east-west-matrix?limit=0").status_code == 422

    def test_limit_101_returns_422(self, client):
        assert client.get("/api/v1/analytics/east-west-matrix?limit=101").status_code == 422


class TestEastWestMatrixAuth:
    def test_requires_auth_returns_401(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/east-west-matrix").status_code == 401


class TestEastWestMatrixData:
    def test_rfc1918_to_rfc1918_counted(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1")

        data = client.get("/api/v1/analytics/east-west-matrix").json()
        assert len(data["rows"]) == 1
        assert data["rows"][0]["src"] == "10.0.0.1"
        assert data["rows"][0]["dst"] == "192.168.1.1"

    def test_rfc1918_to_public_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="8.8.8.8")

        data = client.get("/api/v1/analytics/east-west-matrix").json()
        assert data["rows"] == []

    def test_public_to_rfc1918_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="8.8.8.8", destination_ip="10.0.0.1")

        data = client.get("/api/v1/analytics/east-west-matrix").json()
        assert data["rows"] == []

    def test_both_public_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="1.1.1.1", destination_ip="8.8.8.8")

        data = client.get("/api/v1/analytics/east-west-matrix").json()
        assert data["rows"] == []

    def test_ordered_by_count_desc(self, client, tmp_db):
        for _ in range(5):
            _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1")
        for _ in range(2):
            _insert_log(tmp_db, source_ip="10.0.0.2", destination_ip="192.168.1.2")

        data = client.get("/api/v1/analytics/east-west-matrix").json()
        assert data["rows"][0]["src"] == "10.0.0.1"
        assert data["rows"][0]["dst"] == "192.168.1.1"
        assert data["rows"][0]["count"] == 5

    def test_limit_restricts_result_count(self, client, tmp_db):
        for i in range(5):
            _insert_log(tmp_db, source_ip=f"10.0.{i}.1", destination_ip=f"192.168.{i}.1")

        data = client.get("/api/v1/analytics/east-west-matrix?limit=2").json()
        assert len(data["rows"]) <= 2

    def test_max_count_equals_highest_count(self, client, tmp_db):
        for _ in range(7):
            _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1")
        for _ in range(3):
            _insert_log(tmp_db, source_ip="10.0.0.2", destination_ip="192.168.1.2")

        data = client.get("/api/v1/analytics/east-west-matrix").json()
        assert data["max_count"] == 7

    def test_old_logs_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1",
                    received_at_minutes_ago=180)

        data = client.get("/api/v1/analytics/east-west-matrix?hours=1").json()
        assert data["rows"] == []


class TestEastWestMatrixTenantIsolation:
    def test_tenant_isolation(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", destination_ip="192.168.1.1",
                    tenant_id="default")
        _insert_log(tmp_db, source_ip="10.0.0.2", destination_ip="192.168.1.2",
                    tenant_id="other-tenant")

        data = client.get("/api/v1/analytics/east-west-matrix").json()
        srcs = [r["src"] for r in data["rows"]]
        assert "10.0.0.1" in srcs
        assert "10.0.0.2" not in srcs

    def test_superadmin_sees_all(self, superadmin_client, tmp_db):
        _insert_log(tmp_db, source_ip="10.1.0.1", destination_ip="192.168.2.1",
                    tenant_id="default")
        _insert_log(tmp_db, source_ip="10.1.0.2", destination_ip="192.168.2.2",
                    tenant_id="other-tenant")

        data = superadmin_client.get("/api/v1/analytics/east-west-matrix").json()
        srcs = [r["src"] for r in data["rows"]]
        assert "10.1.0.1" in srcs
        assert "10.1.0.2" in srcs
