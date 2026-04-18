"""
Uptime Checker testleri.
"""

import asyncio
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from server.uptime_checker import ping, tcp_check, http_check, check_device, _looks_like_ip


class TestLooksLikeIp:
    def test_valid_ips(self):
        assert _looks_like_ip("192.168.1.1") is True
        assert _looks_like_ip("10.0.0.1") is True
        assert _looks_like_ip("0.0.0.0") is True

    def test_invalid(self):
        assert _looks_like_ip("hostname") is False
        assert _looks_like_ip("agent-uuid-1") is False
        assert _looks_like_ip("256.0.0.1") is False
        assert _looks_like_ip("") is False


class TestPing:
    def test_unreachable_host_returns_dict(self):
        result = asyncio.new_event_loop().run_until_complete(
            ping("192.0.2.1", count=1, timeout=1)
        )
        assert isinstance(result, dict)
        assert "reachable" in result
        assert "rtt_ms" in result
        assert "packet_loss_pct" in result
        assert "error" in result
        assert result["reachable"] is False

    def test_localhost_reachable(self):
        result = asyncio.new_event_loop().run_until_complete(
            ping("127.0.0.1", count=1, timeout=2)
        )
        assert isinstance(result, dict)
        assert result["reachable"] is True
        assert result["rtt_ms"] is not None

    def test_timeout_returns_false(self):
        # 0.1 saniye timeout → kesinlikle timeout olur
        result = asyncio.new_event_loop().run_until_complete(
            ping("192.0.2.1", count=1, timeout=0)
        )
        assert result["reachable"] is False


class TestTcpCheck:
    def test_closed_port_returns_false(self):
        result = asyncio.new_event_loop().run_until_complete(
            tcp_check("127.0.0.1", 19999, timeout=1)
        )
        assert result["reachable"] is False
        assert result["rtt_ms"] is None

    def test_result_has_required_keys(self):
        result = asyncio.new_event_loop().run_until_complete(
            tcp_check("192.0.2.1", 80, timeout=0.5)
        )
        assert "reachable" in result
        assert "rtt_ms" in result
        assert "error" in result

    def test_unreachable_host(self):
        result = asyncio.new_event_loop().run_until_complete(
            tcp_check("192.0.2.1", 80, timeout=1)
        )
        assert result["reachable"] is False


class TestHttpCheck:
    def test_invalid_url_returns_false(self):
        result = asyncio.new_event_loop().run_until_complete(
            http_check("http://192.0.2.1", timeout=1)
        )
        assert result["reachable"] is False
        assert "status_code" in result

    def test_result_structure(self):
        result = asyncio.new_event_loop().run_until_complete(
            http_check("http://192.0.2.1", timeout=0.5)
        )
        assert all(k in result for k in ["reachable", "status_code", "rtt_ms", "error"])


class TestCheckDevice:
    def test_returns_list(self):
        results = asyncio.new_event_loop().run_until_complete(
            check_device("dev-1", "192.0.2.1")
        )
        assert isinstance(results, list)
        # ICMP kontrolü mutlaka olmalı
        icmp_results = [r for r in results if r["check_type"] == "icmp"]
        assert len(icmp_results) == 1

    def test_icmp_result_structure(self):
        results = asyncio.new_event_loop().run_until_complete(
            check_device("dev-1", "192.0.2.1")
        )
        icmp = results[0]
        assert icmp["check_type"] == "icmp"
        assert icmp["device_id"] == "dev-1"
        assert icmp["target"] == "192.0.2.1"
        assert icmp["status"] in ("up", "down")

    def test_unreachable_host_no_tcp_checks(self):
        """Erişilemeyen cihaza TCP kontrol yapılmamalı."""
        results = asyncio.new_event_loop().run_until_complete(
            check_device("dev-1", "192.0.2.1")
        )
        tcp_results = [r for r in results if r["check_type"] == "tcp"]
        # 192.0.2.1 ulaşılamaz → TCP kontrol olmaz
        assert len(tcp_results) == 0


class TestUptimeCheckerRunOnce:
    def test_run_once_no_devices(self, tmp_db):
        """Kayıtlı cihaz yokken boş liste döndürmeli."""
        from server.uptime_checker import UptimeChecker
        checker = UptimeChecker()
        results = asyncio.new_event_loop().run_until_complete(checker.run_once())
        assert results == []

    def test_run_once_non_ip_devices_skipped(self, tmp_db):
        """IP adresi olmayan cihazlar (agent UUID'leri) atlanmalı."""
        tmp_db.save_device("agent-uuid-abc", "web-server", "agent", status="up")
        from server.uptime_checker import UptimeChecker
        checker = UptimeChecker()
        results = asyncio.new_event_loop().run_until_complete(checker.run_once())
        assert results == []
