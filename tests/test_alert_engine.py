"""Alert Engine testleri."""

from datetime import datetime, timezone
from server.alert_engine import AlertEngine
from shared.models import (
    AgentStatus, AlertStatus, CPUMetrics,
    DiskMetrics, MemoryMetrics, MetricSnapshot,
)


def make_snapshot(cpu=10.0, ram_pct=20.0, disk_pct=50.0) -> MetricSnapshot:
    total = 8_000_000_000
    used = int(total * ram_pct / 100)
    return MetricSnapshot(
        agent_id="test-agent",
        hostname="test-host",
        collected_at=datetime.now(timezone.utc),
        status=AgentStatus.ONLINE,
        cpu=CPUMetrics(
            usage_percent=cpu,
            core_count=4,
            load_avg_1m=0.5
        ),
        memory=MemoryMetrics(
            total_bytes=total,
            used_bytes=used,
            available_bytes=total - used,
        ),
        disks=[DiskMetrics(
            mount_point="/",
            total_bytes=100_000_000_000,
            used_bytes=int(100_000_000_000 * disk_pct / 100),
            free_bytes=int(100_000_000_000 * (100 - disk_pct) / 100),
            usage_percent=disk_pct,
        )],
    )


class TestAlertEngine:
    def test_no_alert_normal_conditions(self):
        engine = AlertEngine()
        alerts = engine.evaluate(make_snapshot(cpu=30.0, ram_pct=40.0))
        assert len(alerts) == 0

    def test_cpu_alert_triggered(self):
        engine = AlertEngine()
        alerts = engine.evaluate(make_snapshot(cpu=85.0))
        cpu_alerts = [a for a in alerts if a.metric == "cpu"]
        assert len(cpu_alerts) == 1
        assert cpu_alerts[0].status == AlertStatus.ACTIVE
        assert cpu_alerts[0].value == 85.0

    def test_cpu_alert_not_duplicated(self):
        engine = AlertEngine()
        engine.evaluate(make_snapshot(cpu=85.0))
        alerts2 = engine.evaluate(make_snapshot(cpu=90.0))
        cpu_alerts = [a for a in alerts2 if a.metric == "cpu"]
        assert len(cpu_alerts) == 0  # İkinci kez alert üretmemeli

    def test_cpu_alert_resolved(self):
        engine = AlertEngine()
        engine.evaluate(make_snapshot(cpu=85.0))
        resolved = engine.evaluate(make_snapshot(cpu=30.0))
        cpu_resolved = [a for a in resolved if a.metric == "cpu"]
        assert len(cpu_resolved) == 1
        assert cpu_resolved[0].status == AlertStatus.RESOLVED

    def test_disk_critical_alert(self):
        engine = AlertEngine()
        alerts = engine.evaluate(make_snapshot(disk_pct=95.0))
        disk_alerts = [a for a in alerts if a.metric == "disk"]
        assert len(disk_alerts) == 1
        assert disk_alerts[0].severity.value == "critical"

    def test_multiple_alerts_simultaneously(self):
        engine = AlertEngine()
        alerts = engine.evaluate(make_snapshot(cpu=85.0, ram_pct=90.0))
        assert len(alerts) == 2