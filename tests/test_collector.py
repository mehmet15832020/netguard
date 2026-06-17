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
    _collect_dns_stats,
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

class TestDnsStatsCollector:
    def test_returns_dict(self):
        """_collect_dns_stats her zaman dict döner, exception fırlatmaz."""
        result = _collect_dns_stats()
        assert isinstance(result, dict)

    def test_returns_empty_when_resolvectl_missing(self, monkeypatch):
        """resolvectl yoksa boş dict döner."""
        import subprocess
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("resolvectl not found")),
        )
        result = _collect_dns_stats()
        assert result == {}

    def test_returns_empty_when_nonzero_returncode(self, monkeypatch):
        """resolvectl hata kodu döndürürse boş dict döner."""
        import subprocess
        from unittest.mock import MagicMock

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)

        result = _collect_dns_stats()
        assert result == {}

    def test_parses_transactions_from_output(self, monkeypatch):
        """Geçerli resolvectl çıktısı doğru parse edilmeli."""
        import subprocess
        from unittest.mock import MagicMock

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Transactions\n"
            "Current Transactions: 3\n"
            "Total Transactions: 1042\n"
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)

        result = _collect_dns_stats()
        assert result.get("current_transactions") == 3
        assert result.get("total_transactions") == 1042

    def test_dns_stats_in_snapshot(self):
        """collect_snapshot() dns_stats alanını içermeli."""
        snapshot = collect_snapshot()
        assert hasattr(snapshot, "dns_stats")
        assert isinstance(snapshot.dns_stats, dict)

    def test_dns_stats_in_snapshot_with_mock(self, monkeypatch):
        """Mock resolvectl çıktısıyla snapshot dns_stats dolu gelir."""
        import subprocess
        from unittest.mock import MagicMock

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Current Transactions: 5\n"
            "Total Transactions: 9999\n"
        )
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_result)

        snapshot = collect_snapshot()
        assert snapshot.dns_stats.get("current_transactions") == 5
        assert snapshot.dns_stats.get("total_transactions") == 9999


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
    