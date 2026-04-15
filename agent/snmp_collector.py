"""
NetGuard Agent — SNMP Collector

Router, switch, printer gibi ağ cihazlarını
agent kurmadan SNMP protokolü ile izler.

Desteklenen SNMP versiyonları: v1, v2c
"""

import logging
import asyncio
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger(__name__)

try:
    from pysnmp.hlapi.asyncio import (
        get_cmd, SnmpEngine, CommunityData,
        UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logger.warning("pysnmp kurulu değil — SNMP collector devre dışı")


# Standart SNMP OID'leri
OIDS = {
    "sysDescr":      "1.3.6.1.2.1.1.1.0",   # Cihaz açıklaması
    "sysUpTime":     "1.3.6.1.2.1.1.3.0",   # Uptime
    "sysName":       "1.3.6.1.2.1.1.5.0",   # Hostname
    "ifInOctets":    "1.3.6.1.2.1.2.2.1.10.1",  # Gelen byte (arayüz 1)
    "ifOutOctets":   "1.3.6.1.2.1.2.2.1.16.1",  # Giden byte (arayüz 1)
    "ifOperStatus":  "1.3.6.1.2.1.2.2.1.8.1",   # Arayüz durumu
}


class SNMPDeviceInfo(BaseModel):
    """SNMP ile elde edilen cihaz bilgisi."""
    host: str
    community: str = "public"
    sys_descr: str = ""
    sys_name: str = ""
    uptime_ticks: int = 0
    if_in_octets: int = 0
    if_out_octets: int = 0
    if_oper_status: int = 0
    reachable: bool = False
    error: str = ""


async def _snmp_get(host: str, community: str, oid: str) -> Optional[str]:
    """Tek bir OID değerini SNMP GET ile çeker."""
    if not SNMP_AVAILABLE:
        return None
    try:
        transport = await UdpTransportTarget.create((host, 161), timeout=2, retries=1)
        errorIndication, errorStatus, _, varBinds = await get_cmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        if errorIndication or errorStatus:
            return None
        for varBind in varBinds:
            return str(varBind[1])
    except Exception:
        return None


async def poll_device_async(host: str, community: str = "public") -> SNMPDeviceInfo:
    """Bir cihazı SNMP ile asenkron olarak sorgular."""
    info = SNMPDeviceInfo(host=host, community=community)

    if not SNMP_AVAILABLE:
        info.error = "pysnmp kurulu değil"
        return info

    try:
        results = await asyncio.gather(
            _snmp_get(host, community, OIDS["sysDescr"]),
            _snmp_get(host, community, OIDS["sysName"]),
            _snmp_get(host, community, OIDS["sysUpTime"]),
            _snmp_get(host, community, OIDS["ifInOctets"]),
            _snmp_get(host, community, OIDS["ifOutOctets"]),
            _snmp_get(host, community, OIDS["ifOperStatus"]),
            return_exceptions=True
        )

        def _str(v) -> str:
            return str(v) if v and not isinstance(v, Exception) else ""

        def _int(v) -> int:
            try:
                return int(v) if v and not isinstance(v, Exception) else 0
            except (ValueError, TypeError):
                return 0

        info.sys_descr      = _str(results[0])
        info.sys_name       = _str(results[1])
        info.uptime_ticks   = _int(results[2])
        info.if_in_octets   = _int(results[3])
        info.if_out_octets  = _int(results[4])
        info.if_oper_status = _int(results[5])
        info.reachable = bool(info.sys_descr or info.sys_name or info.uptime_ticks)

    except Exception as e:
        info.error = str(e)
        info.reachable = False

    return info


def poll_device(host: str, community: str = "public") -> SNMPDeviceInfo:
    """Senkron wrapper — async fonksiyonu sync olarak çağırır."""
    try:
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(poll_device_async(host, community))
    except Exception as e:
        return SNMPDeviceInfo(host=host, error=str(e))