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
        getCmd, SnmpEngine, CommunityData,
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
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((host, 161), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        errorIndication, errorStatus, _, varBinds = await iterator
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

        info.sys_descr = str(results[0]) if results[0] else ""
        info.sys_name = str(results[1]) if results[1] else ""
        info.uptime_ticks = int(results[2]) if results[2] else 0
        info.if_in_octets = int(results[3]) if results[3] else 0
        info.if_out_octets = int(results[4]) if results[4] else 0
        info.if_oper_status = int(results[5]) if results[5] else 0
        info.reachable = True

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