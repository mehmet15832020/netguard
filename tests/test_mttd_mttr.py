"""
Analytics — MTTD / MTTR Metrik Paneli
GET /api/v1/analytics/mttd-mttr

SLA hedefleri: SANS 2023 Incident Response Survey + Prophet Security benchmarks
MTTD: critical<15dk, high<60dk, warning<240dk, info<1440dk
MTTR: critical<60dk, high<120dk, warning<480dk, info<1440dk
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from server.main import app

_client = TestClient(app)


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


def _insert_incident(
    tmp_db,
    severity="high",
    status="resolved",
    created_days_ago=1,
    ack_offset_minutes=30,        # MTTD = ack_offset_minutes dakika sonra
    resolved_offset_minutes=90,   # MTTR = resolved_offset_minutes dakika sonra
    tenant_id="default",
):
    """
    Incident ekler.
    ack_offset_minutes=None → acknowledged_at yok (MTTD hesaplanamaz)
    resolved_offset_minutes=None → resolved_at yok (MTTR hesaplanamaz)
    """
    now = datetime.now(timezone.utc)
    created_dt = now - timedelta(days=created_days_ago)
    ack_dt = (
        (created_dt + timedelta(minutes=ack_offset_minutes)).isoformat()
        if ack_offset_minutes is not None else None
    )
    res_dt = (
        (created_dt + timedelta(minutes=resolved_offset_minutes)).isoformat()
        if resolved_offset_minutes is not None else None
    )
    with tmp_db._connect() as conn:
        conn.execute(
            """
            INSERT INTO incidents
              (incident_id, title, severity, status, created_by,
               created_at, updated_at, resolved_at, acknowledged_at, tenant_id)
            VALUES (%s, 'Test Incident', %s, %s, 'system',
                    %s, %s, %s, %s, %s)
            """,
            (
                str(uuid.uuid4()), severity, status,
                created_dt.isoformat(), created_dt.isoformat(),
                res_dt, ack_dt, tenant_id,
            ),
        )


# ─── Temel yapı ──────────────────────────────────────────────────────────────

class TestMttdMttrBasic:
    def test_endpoint_returns_200(self, client):
        assert client.get("/api/v1/analytics/mttd-mttr").status_code == 200

    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/mttd-mttr").status_code == 401

    def test_days_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/mttd-mttr?days=0").status_code == 422

    def test_days_91_returns_422(self, client):
        assert client.get("/api/v1/analytics/mttd-mttr?days=91").status_code == 422

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        for key in (
            "days", "total_incidents", "resolved_incidents", "acknowledged_incidents",
            "resolution_rate", "overall_mttd_minutes", "overall_mttr_minutes",
            "trend", "by_severity",
        ):
            assert key in data

    def test_empty_db_returns_defaults(self, client):
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["total_incidents"] == 0
        assert data["resolution_rate"] == 0.0
        assert data["overall_mttd_minutes"] is None
        assert data["overall_mttr_minutes"] is None
        assert data["trend"] != []   # zero-filled days döner
        assert data["by_severity"] == []

    def test_trend_has_days_plus_one_entries(self, client):
        data = client.get("/api/v1/analytics/mttd-mttr?days=7").json()
        assert len(data["trend"]) == 8  # days + 1 (since..now dahil)


# ─── Hesaplama doğruluğu ─────────────────────────────────────────────────────

class TestMttdMttrCalculations:
    def test_mttd_calculation_correct(self, client, tmp_db):
        _insert_incident(tmp_db, ack_offset_minutes=20, resolved_offset_minutes=None,
                         status="acknowledged")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["overall_mttd_minutes"] == pytest.approx(20.0, abs=1.0)

    def test_mttr_calculation_correct(self, client, tmp_db):
        _insert_incident(tmp_db, resolved_offset_minutes=60, ack_offset_minutes=None,
                         status="resolved")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["overall_mttr_minutes"] == pytest.approx(60.0, abs=1.0)

    def test_overall_is_average_across_incidents(self, client, tmp_db):
        _insert_incident(tmp_db, ack_offset_minutes=10, resolved_offset_minutes=None,
                         status="acknowledged")
        _insert_incident(tmp_db, ack_offset_minutes=30, resolved_offset_minutes=None,
                         status="acknowledged")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["overall_mttd_minutes"] == pytest.approx(20.0, abs=1.0)

    def test_unacknowledged_incident_excluded_from_mttd(self, client, tmp_db):
        _insert_incident(tmp_db, ack_offset_minutes=None, resolved_offset_minutes=None,
                         status="open")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["overall_mttd_minutes"] is None
        assert data["acknowledged_incidents"] == 0

    def test_unresolved_incident_excluded_from_mttr(self, client, tmp_db):
        _insert_incident(tmp_db, resolved_offset_minutes=None, ack_offset_minutes=10,
                         status="acknowledged")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["overall_mttr_minutes"] is None

    def test_resolution_rate_100_when_all_resolved(self, client, tmp_db):
        for _ in range(3):
            _insert_incident(tmp_db, status="resolved")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["resolution_rate"] == 100.0
        assert data["resolved_incidents"] == 3

    def test_resolution_rate_partial(self, client, tmp_db):
        _insert_incident(tmp_db, status="resolved")
        _insert_incident(tmp_db, status="open", resolved_offset_minutes=None,
                         ack_offset_minutes=None)
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["resolution_rate"] == 50.0

    def test_days_filter_excludes_old_incidents(self, client, tmp_db):
        _insert_incident(tmp_db, created_days_ago=40, status="resolved")
        data = client.get("/api/v1/analytics/mttd-mttr?days=30").json()
        assert data["total_incidents"] == 0

    def test_total_incidents_counts_all_statuses(self, client, tmp_db):
        _insert_incident(tmp_db, status="open", ack_offset_minutes=None,
                         resolved_offset_minutes=None)
        _insert_incident(tmp_db, status="resolved")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["total_incidents"] == 2

    def test_closed_counts_as_resolved(self, client, tmp_db):
        _insert_incident(tmp_db, status="closed")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["resolved_incidents"] == 1


# ─── Veri kalitesi kontrolleri ───────────────────────────────────────────────

class TestMttdMttrDataQuality:
    def test_negative_diff_skipped(self, client, tmp_db):
        # acknowledged_at < created_at → negatif MTTD, atlanmalı
        now = datetime.now(timezone.utc)
        with tmp_db._connect() as conn:
            created = now - timedelta(hours=1)
            ack = created - timedelta(minutes=10)  # ÖNCE onaylandı (veri hatası)
            conn.execute(
                """
                INSERT INTO incidents
                  (incident_id, title, severity, status, created_by,
                   created_at, updated_at, acknowledged_at, tenant_id)
                VALUES (%s, 'Bad', 'high', 'acknowledged', 'system',
                        %s, %s, %s, 'default')
                """,
                (str(uuid.uuid4()), created.isoformat(), created.isoformat(),
                 ack.isoformat()),
            )
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        # Negatif diff atlandı → overall_mttd_minutes None
        assert data["overall_mttd_minutes"] is None

    def test_outlier_diff_skipped(self, client, tmp_db):
        # MTTR > 30 gün → outlier, atlanmalı
        now = datetime.now(timezone.utc)
        with tmp_db._connect() as conn:
            created = now - timedelta(days=25)
            resolved = created + timedelta(days=31)  # 31 gün sonra
            conn.execute(
                """
                INSERT INTO incidents
                  (incident_id, title, severity, status, created_by,
                   created_at, updated_at, resolved_at, tenant_id)
                VALUES (%s, 'Old', 'high', 'resolved', 'system',
                        %s, %s, %s, 'default')
                """,
                (str(uuid.uuid4()), created.isoformat(), created.isoformat(),
                 resolved.isoformat()),
            )
        data = client.get("/api/v1/analytics/mttd-mttr?days=90").json()
        assert data["overall_mttr_minutes"] is None


# ─── Severity breakdown & SLA ────────────────────────────────────────────────

class TestMttdMttrSeverity:
    def test_severity_breakdown_present(self, client, tmp_db):
        _insert_incident(tmp_db, severity="critical", ack_offset_minutes=10,
                         resolved_offset_minutes=30)
        _insert_incident(tmp_db, severity="high", ack_offset_minutes=50,
                         resolved_offset_minutes=100)
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        severities = [b["severity"] for b in data["by_severity"]]
        assert "critical" in severities
        assert "high" in severities

    def test_severity_entry_has_required_fields(self, client, tmp_db):
        _insert_incident(tmp_db, severity="high")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        entry = data["by_severity"][0]
        for field in ("severity", "count", "avg_mttd_minutes", "avg_mttr_minutes",
                      "mttd_sla_pct", "mttr_sla_pct",
                      "mttd_target_minutes", "mttr_target_minutes"):
            assert field in entry

    def test_mttd_sla_100_when_all_meet_target(self, client, tmp_db):
        # Critical MTTD target: 15 dk → 5 dk ile %100
        _insert_incident(tmp_db, severity="critical", ack_offset_minutes=5,
                         resolved_offset_minutes=None, status="acknowledged")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        critical = next(b for b in data["by_severity"] if b["severity"] == "critical")
        assert critical["mttd_sla_pct"] == 100.0

    def test_mttd_sla_0_when_none_meet_target(self, client, tmp_db):
        # Critical MTTD target: 15 dk → 60 dk ile %0
        _insert_incident(tmp_db, severity="critical", ack_offset_minutes=60,
                         resolved_offset_minutes=None, status="acknowledged")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        critical = next(b for b in data["by_severity"] if b["severity"] == "critical")
        assert critical["mttd_sla_pct"] == 0.0

    def test_sla_target_values_match_benchmarks(self, client, tmp_db):
        _insert_incident(tmp_db, severity="critical")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        critical = next(b for b in data["by_severity"] if b["severity"] == "critical")
        assert critical["mttd_target_minutes"] == 15   # SANS benchmark
        assert critical["mttr_target_minutes"] == 60   # Prophet Security benchmark

    def test_severity_without_ack_has_no_mttd_sla(self, client, tmp_db):
        _insert_incident(tmp_db, severity="high", ack_offset_minutes=None,
                         resolved_offset_minutes=None, status="open")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        high = next((b for b in data["by_severity"] if b["severity"] == "high"), None)
        assert high is not None
        assert high["avg_mttd_minutes"] is None
        assert high["mttd_sla_pct"] == 0.0


# ─── Tenant izolasyonu ───────────────────────────────────────────────────────

class TestMttdMttrTenantIsolation:
    def test_tenant_isolation(self, client, tmp_db):
        _insert_incident(tmp_db, tenant_id="default")
        _insert_incident(tmp_db, tenant_id="other-tenant")
        data = client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["total_incidents"] == 1

    def test_superadmin_sees_all_tenants(self, superadmin_client, tmp_db):
        _insert_incident(tmp_db, tenant_id="default")
        _insert_incident(tmp_db, tenant_id="other-tenant")
        data = superadmin_client.get("/api/v1/analytics/mttd-mttr").json()
        assert data["total_incidents"] == 2
