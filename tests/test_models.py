"""
shared/models.py için birim testler.

Kural: Her model için en az bir test.
Kural: Geçersiz veri verildiğinde hata fırlatıldığını test et.
"""

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError
from shared.models import (
    CPUMetrics,
    MemoryMetrics,
    DiskMetrics,
    NetworkInterfaceMetrics,
    MetricSnapshot,
    AgentStatus,
)


class TestCPUMetrics:
    def test_valid_cpu_metrics(self):
        cpu = CPUMetrics(usage_percent=45.5, core_count=4, load_avg_1m=1.2)
        assert cpu.usage_percent == 45.5
        assert cpu.core_count == 4

    def test_usage_percent_cannot_exceed_100(self):
        with pytest.raises(ValidationError):
            CPUMetrics(usage_percent=101.0, core_count=4, load_avg_1m=0.5)

    def test_usage_percent_cannot_be_negative(self):
        with pytest.raises(ValidationError):
            CPUMetrics(usage_percent=-1.0, core_count=4, load_avg_1m=0.5)

    def test_core_count_must_be_positive(self):
        with pytest.raises(ValidationError):
            CPUMetrics(usage_percent=50.0, core_count=0, load_avg_1m=0.5)


class TestMemoryMetrics:
    def test_valid_memory_metrics(self):
        mem = MemoryMetrics(
            total_bytes=16_000_000_000,
            used_bytes=4_000_000_000,
            available_bytes=12_000_000_000,
        )
        assert mem.usage_percent == 25.0

    def test_usage_percent_calculated_correctly(self):
        mem = MemoryMetrics(
            total_bytes=1000,
            used_bytes=750,
            available_bytes=250,
        )
        assert mem.usage_percent == 75.0

    def test_zero_total_returns_zero_percent(self):
        mem = MemoryMetrics(total_bytes=0, used_bytes=0, available_bytes=0)
        assert mem.usage_percent == 0.0


class TestMetricSnapshot:
    def test_valid_snapshot(self):
        snapshot = MetricSnapshot(
            agent_id="agent-001",
            hostname="test-machine",
            collected_at=datetime.now(timezone.utc),
            status=AgentStatus.ONLINE,
            cpu=CPUMetrics(usage_percent=30.0, core_count=4, load_avg_1m=0.8),
            memory=MemoryMetrics(
                total_bytes=8_000_000_000,
                used_bytes=2_000_000_000,
                available_bytes=6_000_000_000,
            ),
        )
        assert snapshot.agent_id == "agent-001"
        assert snapshot.status == AgentStatus.ONLINE
        assert snapshot.disks == []
        assert snapshot.network_interfaces == []

    def test_snapshot_serializes_to_json(self):
        snapshot = MetricSnapshot(
            agent_id="agent-001",
            hostname="test-machine",
            collected_at=datetime.now(timezone.utc),
            cpu=CPUMetrics(usage_percent=30.0, core_count=4, load_avg_1m=0.8),
            memory=MemoryMetrics(
                total_bytes=8_000_000_000,
                used_bytes=2_000_000_000,
                available_bytes=6_000_000_000,
            ),
        )
        json_str = snapshot.model_dump_json()
        assert "agent-001" in json_str
        assert "test-machine" in json_str