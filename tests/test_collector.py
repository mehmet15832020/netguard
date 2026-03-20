"""
agent/collector.py için testler.

Gerçek sistem çağrıları yapılır — bu entegrasyon testidir.
Mock kullanmıyoruz çünkü psutil'in doğru çalıştığını da test ediyoruz.
"""

from agent.collector import (
    collect_snapshot,
    _collect_cpu,
    _collect_memory,
    _collect_disks,
    _collect_network,
    _get_agent_id,
)
from shared.models import AgentStatus


class TestAgentId:
    def test_agent_id_is_string(self):
        agent_id = _get_agent_id()
        assert isinstance(agent_id, str)
        assert len(agent_id) > 0

    def test_agent_id_is_consistent(self):
        """Aynı makinede her çağrıda aynı ID dönmeli."""
        assert _get_agent_id() == _get_agent_id()


class TestCollectors:
    def test_cpu_metrics_valid_range(self):
        cpu = _collect_cpu()
        assert 0.0 <= cpu.usage_percent <= 100.0
        assert cpu.core_count >= 1
        assert cpu.load_avg_1m >= 0.0

    def test_memory_metrics_consistent(self):
        mem = _collect_memory()
        assert mem.total_bytes > 0
        assert mem.used_bytes <= mem.total_bytes
        assert mem.available_bytes <= mem.total_bytes

    def test_disk_metrics_not_empty(self):
        disks = _collect_disks()
        assert len(disks) >= 1
        for disk in disks:
            assert disk.total_bytes > 0
            assert 0.0 <= disk.usage_percent <= 100.0

    def test_network_interfaces_not_empty(self):
        interfaces = _collect_network()
        assert len(interfaces) >= 1
        for iface in interfaces:
            assert len(iface.interface_name) > 0


class TestCollectSnapshot:
    def test_snapshot_is_complete(self):
        snapshot = collect_snapshot()
        assert snapshot.agent_id
        assert snapshot.hostname
        assert snapshot.collected_at
        assert snapshot.cpu
        assert snapshot.memory
        assert snapshot.status in (AgentStatus.ONLINE, AgentStatus.DEGRADED)

    def test_snapshot_has_disks_and_network(self):
        snapshot = collect_snapshot()
        assert len(snapshot.disks) >= 1
        assert len(snapshot.network_interfaces) >= 1