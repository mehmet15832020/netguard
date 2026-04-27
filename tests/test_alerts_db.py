"""
Alert storage ve retrieval testleri — SQLite tabanlı.
In-memory storage kaldırıldıktan sonra tüm alert okuma/yazma db üzerinden gider.
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from server.alert_engine import AlertEngine
from server.database import DatabaseManager
from shared.models import (
    AgentStatus, Alert, AlertSeverity, AlertStatus,
    CPUMetrics, DiskMetrics, MemoryMetrics, MetricSnapshot,
)


def _make_alert(agent_id="agent-1", metric="cpu", status=AlertStatus.ACTIVE) -> Alert:
    return Alert(
        alert_id=str(uuid.uuid4()),
        agent_id=agent_id,
        hostname="test-host",
        severity=AlertSeverity.WARNING,
        status=status,
        metric=metric,
        message="test alert",
        value=90.0,
        threshold=80.0,
        triggered_at=datetime.now(timezone.utc),
    )


def _make_snapshot(cpu=10.0, ram_pct=20.0, disk_pct=50.0) -> MetricSnapshot:
    total = 8_000_000_000
    used = int(total * ram_pct / 100)
    return MetricSnapshot(
        agent_id="test-agent",
        hostname="test-host",
        collected_at=datetime.now(timezone.utc),
        status=AgentStatus.ONLINE,
        cpu=CPUMetrics(usage_percent=cpu, core_count=4, load_avg_1m=0.5),
        memory=MemoryMetrics(
            total_bytes=total, used_bytes=used, available_bytes=total - used
        ),
        disks=[DiskMetrics(
            mount_point="/",
            total_bytes=100_000_000_000,
            used_bytes=int(100_000_000_000 * disk_pct / 100),
            free_bytes=int(100_000_000_000 * (100 - disk_pct) / 100),
            usage_percent=disk_pct,
        )],
    )


class TestAlertSQLitePersistence:
    def test_save_and_retrieve(self, tmp_db):
        alert = _make_alert()
        tmp_db.save_alert(alert)

        results = tmp_db.get_alerts()
        assert len(results) == 1
        assert results[0].alert_id == alert.alert_id
        assert results[0].metric == "cpu"

    def test_filter_by_status(self, tmp_db):
        tmp_db.save_alert(_make_alert(metric="cpu",  status=AlertStatus.ACTIVE))
        tmp_db.save_alert(_make_alert(metric="disk", status=AlertStatus.RESOLVED))

        active   = tmp_db.get_alerts(status="active")
        resolved = tmp_db.get_alerts(status="resolved")
        assert len(active)   == 1
        assert len(resolved) == 1

    def test_resolve_updates_existing(self, tmp_db):
        alert = _make_alert()
        tmp_db.save_alert(alert)

        resolved = Alert(
            **{**alert.model_dump(), "status": AlertStatus.RESOLVED,
               "resolved_at": datetime.now(timezone.utc)}
        )
        tmp_db.save_alert(resolved)

        results = tmp_db.get_alerts()
        assert len(results) == 1
        assert results[0].status == AlertStatus.RESOLVED

    def test_limit_respected(self, tmp_db):
        for _ in range(10):
            tmp_db.save_alert(_make_alert())
        results = tmp_db.get_alerts(limit=3)
        assert len(results) == 3

    def test_restart_restores_active_alerts(self, tmp_db):
        """Sunucu restart sonrası AlertEngine aktif alertleri DB'den yüklemeli."""
        engine = AlertEngine()
        snapshot = _make_snapshot(cpu=85.0)
        alerts = engine.evaluate(snapshot)
        assert len(alerts) == 1
        for a in alerts:
            tmp_db.save_alert(a)

        new_engine = AlertEngine()
        new_engine.restore_active_alerts(tmp_db)

        # Aynı alert tekrar üretilmemeli
        duplicate_alerts = new_engine.evaluate(_make_snapshot(cpu=90.0))
        cpu_alerts = [a for a in duplicate_alerts if a.metric == "cpu"]
        assert len(cpu_alerts) == 0

    def test_no_duplicate_after_restore(self, tmp_db):
        """Restore sonrası normal koşulda alert üretilmemeli."""
        engine = AlertEngine()
        alerts = engine.evaluate(_make_snapshot(cpu=85.0))
        for a in alerts:
            tmp_db.save_alert(a)

        engine.restore_active_alerts(tmp_db)
        second_alerts = engine.evaluate(_make_snapshot(cpu=85.0))
        assert len(second_alerts) == 0

    def test_correlator_alerts_excluded_from_restore(self, tmp_db):
        """Correlator alert'leri restore'a dahil edilmemeli."""
        correlator_alert = Alert(
            alert_id=str(uuid.uuid4()),
            agent_id="correlator",
            hostname="192.168.1.1",
            severity=AlertSeverity.CRITICAL,
            status=AlertStatus.ACTIVE,
            metric="port_scan",
            message="Port scan tespit edildi",
            value=50.0,
            threshold=0.0,
            triggered_at=datetime.now(timezone.utc),
        )
        tmp_db.save_alert(correlator_alert)

        engine = AlertEngine()
        engine.restore_active_alerts(tmp_db)
        # Correlator alert'i _active'e eklenmemeli
        assert len(engine._active) == 0


class TestAlertRoute:
    def test_list_alerts_endpoint(self, tmp_db, admin_token):
        from server.main import app
        tmp_db.save_alert(_make_alert())

        import server.routes.alerts as alert_route
        alert_route.db = tmp_db

        client = TestClient(app)
        resp = client.get(
            "/api/v1/alerts",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["alerts"][0]["metric"] == "cpu"

    def test_alert_summary_endpoint(self, tmp_db, admin_token):
        from server.main import app
        import server.routes.alerts as alert_route
        alert_route.db = tmp_db

        tmp_db.save_alert(_make_alert(metric="cpu",  status=AlertStatus.ACTIVE))
        tmp_db.save_alert(_make_alert(metric="disk", status=AlertStatus.RESOLVED))

        client = TestClient(app)
        resp = client.get(
            "/api/v1/alerts/summary",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["active"]   == 1
        assert data["resolved"] == 1
        assert data["total"]    == 2


class TestSchemaVersion:
    def test_schema_version_set(self, tmp_db):
        version = tmp_db.get_schema_version()
        assert version >= 1
