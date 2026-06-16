"""
SNMP Collector testleri.

Gerçek bir SNMP cihazı gerektiren testler atlanır (skip).
Sadece erişilebilir host'lar (localhost, 127.0.0.1) üzerinde çalışır.
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock
from server.snmp_collector import (
    SNMPDeviceInfo,
    SNMPInterface,
    poll_device,
    poll_device_async,
    _run_snmpget,
    SNMP_AVAILABLE,
    OIDS,
)


class TestSNMPDeviceInfo:
    def test_default_values(self):
        info = SNMPDeviceInfo(host="192.168.1.1")
        assert info.host == "192.168.1.1"
        assert info.community == "public"
        assert info.reachable is False
        assert info.sys_name == ""
        assert info.uptime_ticks == 0

    def test_custom_community(self):
        info = SNMPDeviceInfo(host="10.0.0.1", community="private")
        assert info.community == "private"

    def test_serializable(self):
        info = SNMPDeviceInfo(host="1.2.3.4", reachable=True, sys_name="router")
        d = info.model_dump()
        assert d["host"] == "1.2.3.4"
        assert d["reachable"] is True
        assert d["sys_name"] == "router"

    def test_backward_compat_properties(self):
        iface = SNMPInterface(index="1", oper_status=1, hc_in_octets=1000, hc_out_octets=500)
        info = SNMPDeviceInfo(host="1.2.3.4", interfaces=[iface])
        assert info.if_oper_status == 1
        assert info.if_in_octets == 1000
        assert info.if_out_octets == 500

    def test_backward_compat_empty_interfaces(self):
        info = SNMPDeviceInfo(host="1.2.3.4")
        assert info.if_oper_status == 0
        assert info.if_in_octets == 0


class TestOIDs:
    def test_required_oids_present(self):
        for key in ["sysDescr", "sysUpTime", "sysName", "ifInOctets", "ifOutOctets", "ifOperStatus"]:
            assert key in OIDS
            assert OIDS[key].startswith("1.3.6.1")


class TestPollDeviceUnreachable:
    def test_unreachable_host_returns_info(self):
        """Ulaşılamayan host — exception değil SNMPDeviceInfo dönmeli."""
        result = poll_device("192.0.2.1", community="public")  # TEST-NET, ulaşılamaz
        assert isinstance(result, SNMPDeviceInfo)
        assert result.host == "192.0.2.1"
        assert result.reachable is False

    def test_unreachable_host_has_error_or_empty(self):
        result = poll_device("192.0.2.1")
        assert isinstance(result.error, str)


class TestPollDeviceAsync:
    def test_snmp_unavailable_returns_error(self):
        """snmpget yoksa reachable=False ve error dolu dönmeli."""
        with patch("server.snmp_collector.SNMP_AVAILABLE", False):
            result = asyncio.new_event_loop().run_until_complete(
                poll_device_async("127.0.0.1")
            )
        assert result.reachable is False
        assert result.error != ""

    def test_poll_returns_snmpdeviceinfo(self):
        result = asyncio.new_event_loop().run_until_complete(
            poll_device_async("192.0.2.1")
        )
        assert isinstance(result, SNMPDeviceInfo)

    def test_exception_in_snmpget_handled(self):
        """_run_snmpget hata verirse exception propagate edilmemeli."""
        async def failing_get(*args, **kwargs):
            raise ConnectionError("test hatası")

        with patch("server.snmp_collector._run_snmpget", side_effect=failing_get):
            result = asyncio.new_event_loop().run_until_complete(
                poll_device_async("127.0.0.1")
            )
        assert isinstance(result, SNMPDeviceInfo)
        assert result.reachable is False


class TestRunSnmpget:
    def test_snmp_unavailable_via_poll(self):
        with patch("server.snmp_collector.SNMP_AVAILABLE", False):
            result = asyncio.new_event_loop().run_until_complete(
                poll_device_async("127.0.0.1")
            )
        assert result.reachable is False

    def test_unreachable_returns_empty(self):
        """Timeout olan host boş dict döndürmeli, exception fırlatmamalı."""
        result = asyncio.new_event_loop().run_until_complete(
            _run_snmpget("192.0.2.1", [OIDS["sysName"]], ["-v2c", "-c", "public"])
        )
        assert isinstance(result, dict)


@pytest.mark.skipif(not SNMP_AVAILABLE, reason="snmpget CLI aracı bulunamadı")
class TestSNMPAvailable:
    def test_snmpget_accessible(self):
        import shutil
        assert shutil.which("snmpget") is not None


class TestInterfaceStatsFlag:
    """D2 — SNMP_COLLECT_INTERFACE_STATS varsayılan false; sadece link state toplanır."""

    @staticmethod
    def _mock_walk(_host: str, base_oid: str, *_args, **_kwargs):
        from server.snmp_collector import IF_TABLE_OIDS
        if base_oid == IF_TABLE_OIDS["ifDescr"]:
            return {"1": "eth0"}
        if base_oid == IF_TABLE_OIDS["ifOperStatus"]:
            return {"1": "1"}
        if base_oid in (IF_TABLE_OIDS["ifHCInOctets"], IF_TABLE_OIDS["ifHCOutOctets"]):
            return {"1": "123456"}
        if base_oid in (IF_TABLE_OIDS["ifInErrors"], IF_TABLE_OIDS["ifOutErrors"], IF_TABLE_OIDS["ifInDiscards"]):
            return {"1": "0"}
        return {}

    def _run(self):
        async def _go():
            mock_walk = AsyncMock(side_effect=self._mock_walk)
            with patch("server.snmp_collector._run_snmpget", AsyncMock(return_value={
                "1.3.6.1.2.1.1.1.0": "Test Device", "1.3.6.1.2.1.1.2.0": "1.2.3",
                "1.3.6.1.2.1.1.3.0": "12345", "1.3.6.1.2.1.1.5.0": "test-host",
            })), patch("server.snmp_collector._run_snmpwalk", mock_walk):
                result = await poll_device_async("127.0.0.1")
            return result, mock_walk

        return asyncio.new_event_loop().run_until_complete(_go())

    def test_stats_disabled_by_default_skips_octet_walks(self):
        with patch("server.snmp_collector.SNMP_COLLECT_INTERFACE_STATS", False):
            result, mock_walk = self._run()

        walked_oids = {call.args[1] for call in mock_walk.call_args_list}
        from server.snmp_collector import IF_TABLE_OIDS
        assert IF_TABLE_OIDS["ifHCInOctets"] not in walked_oids
        assert IF_TABLE_OIDS["ifInErrors"] not in walked_oids
        assert IF_TABLE_OIDS["ifDescr"] in walked_oids
        assert IF_TABLE_OIDS["ifOperStatus"] in walked_oids

    def test_stats_disabled_link_state_still_populated(self):
        with patch("server.snmp_collector.SNMP_COLLECT_INTERFACE_STATS", False):
            result, _ = self._run()

        assert len(result.interfaces) == 1
        assert result.interfaces[0].oper_status == 1
        assert result.interfaces[0].hc_in_octets == 0

    def test_stats_enabled_collects_octets(self):
        with patch("server.snmp_collector.SNMP_COLLECT_INTERFACE_STATS", True):
            result, mock_walk = self._run()

        from server.snmp_collector import IF_TABLE_OIDS
        walked_oids = {call.args[1] for call in mock_walk.call_args_list}
        assert IF_TABLE_OIDS["ifHCInOctets"] in walked_oids
        assert result.interfaces[0].hc_in_octets == 123456
