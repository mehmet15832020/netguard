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

    def test_network_snapshot_present(self):
        """İkinci çağrıda network_snapshot dolu olmalı."""
        collect_snapshot()  # ilk çağrı — referans nokta
        import time; time.sleep(1)
        snapshot = collect_snapshot()  # ikinci çağrı — bant genişliği hesaplı
        assert snapshot.network_snapshot is not None
        assert snapshot.network_snapshot.connections.total >= 0

class TestProcessCollector:
    def test_process_snapshot_collected(self):
        from agent.collector import _collect_processes
        ps = _collect_processes()
        assert ps.total_processes > 0
        assert len(ps.top_cpu) <= 10
        assert len(ps.top_memory) <= 10

    def test_process_snapshot_in_full_snapshot(self):
        snapshot = collect_snapshot()
        # İkinci çağrıda process_snapshot dolu olmalı
        import time; time.sleep(1)
        snapshot2 = collect_snapshot()
        assert snapshot2.process_snapshot is not None
        assert snapshot2.process_snapshot.total_processes > 0
    