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
    poll_device,
    poll_device_async,
    _snmp_get,
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
        # ya error dolu ya da tüm alanlar boş — ama exception yok
        assert isinstance(result.error, str)


class TestPollDeviceAsync:
    def test_snmp_unavailable_returns_error(self):
        """pysnmp yoksa reachable=False ve error dolu dönmeli."""
        with patch("server.snmp_collector.SNMP_AVAILABLE", False):
            result = asyncio.new_event_loop().run_until_complete(
                poll_device_async("127.0.0.1")
            )
        assert result.reachable is False
        assert "pysnmp" in result.error.lower()

    def test_poll_returns_snmpdeviceinfo(self):
        result = asyncio.new_event_loop().run_until_complete(
            poll_device_async("192.0.2.1")
        )
        assert isinstance(result, SNMPDeviceInfo)

    def test_exception_in_gather_handled(self):
        """asyncio.gather'dan gelen Exception nesneleri sessizce işlenmeli — exception yükseltmemeli."""
        async def failing_get(*args, **kwargs):
            raise ConnectionError("test hatası")

        with patch("server.snmp_collector._snmp_get", side_effect=failing_get):
            result = asyncio.new_event_loop().run_until_complete(
                poll_device_async("127.0.0.1")
            )
        # Exception propagate edilmemeli, geçerli bir SNMPDeviceInfo dönmeli
        assert isinstance(result, SNMPDeviceInfo)
        # sys alanları boş olmalı (_snmp_get mock edildi)
        assert result.sys_descr == ""
        assert result.sys_name == ""


class TestSnmpGet:
    def test_snmp_unavailable_returns_none(self):
        with patch("server.snmp_collector.SNMP_AVAILABLE", False):
            result = asyncio.new_event_loop().run_until_complete(
                _snmp_get("127.0.0.1", "public", OIDS["sysName"])
            )
        assert result is None

    def test_unreachable_returns_none(self):
        """Timeout olan host None döndürmeli, exception fırlatmamalı."""
        result = asyncio.new_event_loop().run_until_complete(
            _snmp_get("192.0.2.1", "public", OIDS["sysName"])
        )
        assert result is None


@pytest.mark.skipif(not SNMP_AVAILABLE, reason="pysnmp kurulu değil")
class TestSNMPAvailable:
    def test_import_works(self):
        from server.snmp_collector import get_cmd  # noqa: F401 — sadece import testi
        assert True
