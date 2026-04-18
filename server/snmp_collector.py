"""
NetGuard Server — SNMP Collector v2

Tüm arayüzleri sorgular (interface table walk), 64-bit counter kullanır,
önceki poll ile delta hesaplayarak gerçek bandwidth değeri üretir.

Desteklenen: SNMPv2c (v3 Faz 7'de gelecek)
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel

logger = logging.getLogger(__name__)

try:
    from pysnmp.hlapi.asyncio import (
        get_cmd, next_cmd, SnmpEngine, CommunityData,
        UdpTransportTarget, ContextData, ObjectType, ObjectIdentity,
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logger.warning("pysnmp kurulu değil — SNMP collector devre dışı")

# Sistem OID'leri (tekil değer)
SYSTEM_OIDS = {
    "sysDescr":    "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime":   "1.3.6.1.2.1.1.3.0",
    "sysName":     "1.3.6.1.2.1.1.5.0",
}

# Arayüz tablosu sütun OID'leri (walk ile tüm indeksler çekilir)
IF_TABLE_OIDS = {
    "ifDescr":       "1.3.6.1.2.1.2.2.1.2",      # arayüz adı
    "ifOperStatus":  "1.3.6.1.2.1.2.2.1.8",      # 1=up, 2=down
    "ifHCInOctets":  "1.3.6.1.2.1.31.1.1.1.6",   # 64-bit gelen byte
    "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",  # 64-bit giden byte
    "ifInOctets":    "1.3.6.1.2.1.2.2.1.10",     # 32-bit fallback
    "ifOutOctets":   "1.3.6.1.2.1.2.2.1.16",     # 32-bit fallback
    "ifInErrors":    "1.3.6.1.2.1.2.2.1.14",
    "ifOutErrors":   "1.3.6.1.2.1.2.2.1.20",
    "ifInDiscards":  "1.3.6.1.2.1.2.2.1.13",
}

# Eski OIDS dict'i — backward compat (test_snmp.py kullanıyor)
OIDS = {
    "sysDescr":    SYSTEM_OIDS["sysDescr"],
    "sysUpTime":   SYSTEM_OIDS["sysUpTime"],
    "sysName":     SYSTEM_OIDS["sysName"],
    "ifInOctets":  IF_TABLE_OIDS["ifInOctets"] + ".1",
    "ifOutOctets": IF_TABLE_OIDS["ifOutOctets"] + ".1",
    "ifOperStatus": IF_TABLE_OIDS["ifOperStatus"] + ".1",
}

_MAX_COUNTER32 = 2**32
_MAX_COUNTER64 = 2**64

# Host başına bandwidth delta için önceki poll değerleri
# {host: {if_index: (monotonic_time, hc_in, hc_out)}}
_counter_cache: dict[str, dict[str, tuple[float, int, int]]] = {}


class SNMPInterface(BaseModel):
    """Tek bir ağ arayüzünün SNMP ile ölçülen verileri."""
    index: str
    name: str = ""
    oper_status: int = 0          # 1=up, 2=down
    hc_in_octets: int = 0         # 64-bit gelen byte sayacı
    hc_out_octets: int = 0        # 64-bit giden byte sayacı
    in_errors: int = 0
    out_errors: int = 0
    in_discards: int = 0
    bandwidth_in_bps: float = 0.0
    bandwidth_out_bps: float = 0.0

    @property
    def is_up(self) -> bool:
        return self.oper_status == 1

    @property
    def bandwidth_in_mbps(self) -> float:
        return round(self.bandwidth_in_bps / 1_000_000, 3)

    @property
    def bandwidth_out_mbps(self) -> float:
        return round(self.bandwidth_out_bps / 1_000_000, 3)


class SNMPDeviceInfo(BaseModel):
    """SNMP ile elde edilen cihaz bilgisi — tüm arayüzleri içerir."""
    host: str
    community: str = "public"
    sys_descr: str = ""
    sys_name: str = ""
    sys_object_id: str = ""
    uptime_ticks: int = 0
    interfaces: list[SNMPInterface] = []
    reachable: bool = False
    error: str = ""
    polled_at: Optional[datetime] = None

    # Backward compat — ilk arayüzden türetilir
    @property
    def if_in_octets(self) -> int:
        return self.interfaces[0].hc_in_octets if self.interfaces else 0

    @property
    def if_out_octets(self) -> int:
        return self.interfaces[0].hc_out_octets if self.interfaces else 0

    @property
    def if_oper_status(self) -> int:
        return self.interfaces[0].oper_status if self.interfaces else 0


async def _snmp_get(host: str, community: str, oid: str) -> Optional[str]:
    """Tek OID değerini SNMP GET ile çeker."""
    if not SNMP_AVAILABLE:
        return None
    try:
        transport = await UdpTransportTarget.create((host, 161), timeout=2, retries=1)
        err_ind, err_stat, _, var_binds = await get_cmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        if err_ind or err_stat:
            return None
        for vb in var_binds:
            return str(vb[1])
    except Exception:
        return None
    return None


async def _walk_column(
    engine: "SnmpEngine",
    community_data: "CommunityData",
    transport: "UdpTransportTarget",
    base_oid: str,
) -> dict[str, str]:
    """
    Bir OID sütununu walk ile tarar.
    Döndürür: {instance_index: value} — örn: {"1": "eth0", "2": "lo"}
    """
    results: dict[str, str] = {}
    current_oid = base_oid

    while True:
        try:
            err_ind, err_stat, _, var_binds = await next_cmd(
                engine,
                community_data,
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(current_oid)),
                lookupMib=False,
            )
        except Exception:
            break

        if err_ind or err_stat or not var_binds:
            break

        oid_str = str(var_binds[0][0])
        value = str(var_binds[0][1])

        if not oid_str.startswith(base_oid + "."):
            break  # Farklı tabloya geçildi

        instance = oid_str[len(base_oid) + 1:]
        results[instance] = value
        current_oid = oid_str

    return results


def _calc_bandwidth(
    host: str,
    if_index: str,
    new_in: int,
    new_out: int,
) -> tuple[float, float]:
    """
    Önceki poll ile delta alarak bps hesaplar.
    64-bit overflow düzeltmesi yapar.
    Döndürür: (in_bps, out_bps)
    """
    now = time.monotonic()
    prev = _counter_cache.get(host, {}).get(if_index)

    if prev is None:
        _counter_cache.setdefault(host, {})[if_index] = (now, new_in, new_out)
        return 0.0, 0.0

    prev_time, prev_in, prev_out = prev
    elapsed = now - prev_time

    if elapsed < 1:
        return 0.0, 0.0

    def _delta(new: int, old: int) -> int:
        if new >= old:
            return new - old
        # 64-bit overflow
        return (_MAX_COUNTER64 - old) + new

    in_bps  = _delta(new_in, prev_in)  * 8 / elapsed
    out_bps = _delta(new_out, prev_out) * 8 / elapsed

    _counter_cache.setdefault(host, {})[if_index] = (now, new_in, new_out)
    return round(in_bps, 2), round(out_bps, 2)


async def poll_device_async(host: str, community: str = "public") -> SNMPDeviceInfo:
    """
    Bir cihazı tam olarak sorgular:
    - Sistem OID'leri (GET)
    - Tüm arayüzler (walk)
    - Bandwidth delta hesabı
    """
    info = SNMPDeviceInfo(host=host, community=community)

    if not SNMP_AVAILABLE:
        info.error = "pysnmp kurulu değil"
        return info

    try:
        transport = await UdpTransportTarget.create((host, 161), timeout=2, retries=1)
        engine = SnmpEngine()
        community_data = CommunityData(community, mpModel=1)

        # 1) Sistem OID'leri — asyncio.gather ile paralel GET
        sys_results = await asyncio.gather(
            _snmp_get(host, community, SYSTEM_OIDS["sysDescr"]),
            _snmp_get(host, community, SYSTEM_OIDS["sysObjectID"]),
            _snmp_get(host, community, SYSTEM_OIDS["sysUpTime"]),
            _snmp_get(host, community, SYSTEM_OIDS["sysName"]),
            return_exceptions=True,
        )

        def _s(v) -> str:
            return str(v) if v and not isinstance(v, Exception) else ""

        def _i(v) -> int:
            try:
                return int(v) if v and not isinstance(v, Exception) else 0
            except (ValueError, TypeError):
                return 0

        info.sys_descr     = _s(sys_results[0])
        info.sys_object_id = _s(sys_results[1])
        info.uptime_ticks  = _i(sys_results[2])
        info.sys_name      = _s(sys_results[3])

        # 2) Arayüz tablosu — tüm sütunları walk ile çek
        col_results = await asyncio.gather(
            _walk_column(engine, community_data, transport, IF_TABLE_OIDS["ifDescr"]),
            _walk_column(engine, community_data, transport, IF_TABLE_OIDS["ifOperStatus"]),
            _walk_column(engine, community_data, transport, IF_TABLE_OIDS["ifHCInOctets"]),
            _walk_column(engine, community_data, transport, IF_TABLE_OIDS["ifHCOutOctets"]),
            _walk_column(engine, community_data, transport, IF_TABLE_OIDS["ifInErrors"]),
            _walk_column(engine, community_data, transport, IF_TABLE_OIDS["ifOutErrors"]),
            _walk_column(engine, community_data, transport, IF_TABLE_OIDS["ifInDiscards"]),
            return_exceptions=True,
        )

        def _col(idx: int) -> dict[str, str]:
            r = col_results[idx]
            return r if isinstance(r, dict) else {}

        descr_col      = _col(0)
        status_col     = _col(1)
        hc_in_col      = _col(2)
        hc_out_col     = _col(3)
        in_err_col     = _col(4)
        out_err_col    = _col(5)
        in_disc_col    = _col(6)

        # Eğer 64-bit sütunlar boşsa 32-bit fallback
        if not hc_in_col and not hc_out_col:
            hc_in_col, hc_out_col = await asyncio.gather(
                _walk_column(engine, community_data, transport, IF_TABLE_OIDS["ifInOctets"]),
                _walk_column(engine, community_data, transport, IF_TABLE_OIDS["ifOutOctets"]),
            )

        # Tüm bilinen indeksleri birleştir
        all_indices = (
            set(descr_col) | set(status_col) | set(hc_in_col) | set(hc_out_col)
        )

        for idx in sorted(all_indices, key=lambda x: int(x) if x.isdigit() else 0):
            hc_in  = int(hc_in_col.get(idx, "0") or "0")
            hc_out = int(hc_out_col.get(idx, "0") or "0")
            in_bps, out_bps = _calc_bandwidth(host, idx, hc_in, hc_out)

            iface = SNMPInterface(
                index=idx,
                name=descr_col.get(idx, f"if{idx}"),
                oper_status=int(status_col.get(idx, "2") or "2"),
                hc_in_octets=hc_in,
                hc_out_octets=hc_out,
                in_errors=int(in_err_col.get(idx, "0") or "0"),
                out_errors=int(out_err_col.get(idx, "0") or "0"),
                in_discards=int(in_disc_col.get(idx, "0") or "0"),
                bandwidth_in_bps=in_bps,
                bandwidth_out_bps=out_bps,
            )
            info.interfaces.append(iface)

        info.reachable  = bool(info.sys_descr or info.sys_name or info.interfaces)
        info.polled_at  = datetime.now(timezone.utc)

    except Exception as exc:
        info.error    = str(exc)
        info.reachable = False

    return info


def poll_device(host: str, community: str = "public") -> SNMPDeviceInfo:
    """Senkron wrapper."""
    try:
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(poll_device_async(host, community))
    except Exception as exc:
        return SNMPDeviceInfo(host=host, error=str(exc))
