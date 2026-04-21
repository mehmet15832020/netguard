"""
NetGuard Server — SNMP Collector v3

snmpget / snmpwalk CLI araçlarını subprocess ile çağırır.
pysnmp bağımlılığı yoktur — sistem araçları yeterlidir.

Desteklenen: SNMPv2c ve SNMPv3 (authPriv, authNoPriv, noAuthNoPriv)
"""

import asyncio
import logging
import re
import shutil
import time
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel

logger = logging.getLogger(__name__)

SNMP_AVAILABLE = bool(shutil.which("snmpget"))
if not SNMP_AVAILABLE:
    logger.warning("snmpget bulunamadı — SNMP collector devre dışı")

# Sistem OID'leri
SYSTEM_OIDS = {
    "sysDescr":    "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime":   "1.3.6.1.2.1.1.3.0",
    "sysName":     "1.3.6.1.2.1.1.5.0",
}

IF_TABLE_OIDS = {
    "ifDescr":       "1.3.6.1.2.1.2.2.1.2",
    "ifOperStatus":  "1.3.6.1.2.1.2.2.1.8",
    "ifHCInOctets":  "1.3.6.1.2.1.31.1.1.1.6",
    "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "ifInOctets":    "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets":   "1.3.6.1.2.1.2.2.1.16",
    "ifInErrors":    "1.3.6.1.2.1.2.2.1.14",
    "ifOutErrors":   "1.3.6.1.2.1.2.2.1.20",
    "ifInDiscards":  "1.3.6.1.2.1.2.2.1.13",
}

OIDS = {
    "sysDescr":    SYSTEM_OIDS["sysDescr"],
    "sysUpTime":   SYSTEM_OIDS["sysUpTime"],
    "sysName":     SYSTEM_OIDS["sysName"],
    "ifInOctets":  IF_TABLE_OIDS["ifInOctets"] + ".1",
    "ifOutOctets": IF_TABLE_OIDS["ifOutOctets"] + ".1",
    "ifOperStatus": IF_TABLE_OIDS["ifOperStatus"] + ".1",
}

_MAX_COUNTER64 = 2**64
_counter_cache: dict[str, dict[str, tuple[float, int, int]]] = {}


class SNMPInterface(BaseModel):
    index: str
    name: str = ""
    oper_status: int = 0
    hc_in_octets: int = 0
    hc_out_octets: int = 0
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

    @property
    def if_in_octets(self) -> int:
        return self.interfaces[0].hc_in_octets if self.interfaces else 0

    @property
    def if_out_octets(self) -> int:
        return self.interfaces[0].hc_out_octets if self.interfaces else 0

    @property
    def if_oper_status(self) -> int:
        return self.interfaces[0].oper_status if self.interfaces else 0


def _build_args(
    version: str,
    community: str,
    v3_username: str,
    v3_auth_protocol: str,
    v3_auth_key: str,
    v3_priv_protocol: str,
    v3_priv_key: str,
) -> list[str]:
    """snmpget/snmpwalk için ortak versiyon/auth argümanları."""
    if version == "v3":
        level = "noAuthNoPriv"
        args = ["-v3", "-u", v3_username]
        if v3_auth_key:
            level = "authNoPriv"
            args += ["-a", v3_auth_protocol, "-A", v3_auth_key]
        if v3_priv_key:
            level = "authPriv"
            args += ["-x", v3_priv_protocol, "-X", v3_priv_key]
        args += ["-l", level]
    else:
        args = ["-v2c", "-c", community]
    return args


def _parse_value(raw: str) -> str:
    """
    snmpget/snmpwalk çıktısından değer kısmını ayıklar.
    Format: .OID = TYPE: value
    """
    if "=" not in raw:
        return ""
    value_part = raw.split("=", 1)[1].strip()
    if ":" in value_part:
        value_part = value_part.split(":", 1)[1].strip()
    return value_part.strip('"')


def _parse_uptime(value: str) -> int:
    """
    Uptime değerini timeticks integer'a çevirir.
    Format: '(123456) 0:20:34.56' veya '123456'
    """
    m = re.search(r"\((\d+)\)", value)
    if m:
        return int(m.group(1))
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0


async def _run_snmpget(
    host: str,
    oids: list[str],
    version_args: list[str],
) -> dict[str, str]:
    """snmpget ile birden fazla OID'i tek sorguda çeker."""
    cmd = ["snmpget", "-On", "-t", "2", "-r", "1"] + version_args + [host] + oids
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        results: dict[str, str] = {}
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            oid_part = line.split("=")[0].strip().lstrip(".")
            results[oid_part] = _parse_value(line)
        return results
    except Exception:
        return {}


async def _run_snmpwalk(
    host: str,
    base_oid: str,
    version_args: list[str],
) -> dict[str, str]:
    """
    snmpwalk ile OID sütununu tarar.
    Döndürür: {instance_suffix: value} — örn. {"1": "eth0"}
    """
    cmd = ["snmpwalk", "-On", "-t", "2", "-r", "1"] + version_args + [host, base_oid]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        results: dict[str, str] = {}
        prefix = "." + base_oid.lstrip(".")
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            oid_part = line.split("=")[0].strip()
            if not oid_part.startswith(prefix + "."):
                continue
            suffix = oid_part[len(prefix) + 1:]
            results[suffix] = _parse_value(line)
        return results
    except Exception:
        return {}


def _calc_bandwidth(
    host: str,
    if_index: str,
    new_in: int,
    new_out: int,
) -> tuple[float, float]:
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
        return new - old if new >= old else (_MAX_COUNTER64 - old) + new

    in_bps  = _delta(new_in,  prev_in)  * 8 / elapsed
    out_bps = _delta(new_out, prev_out) * 8 / elapsed
    _counter_cache.setdefault(host, {})[if_index] = (now, new_in, new_out)
    return round(in_bps, 2), round(out_bps, 2)


async def poll_device_async(
    host: str,
    community: str = "public",
    snmp_version: str = "v2c",
    v3_username: str = "",
    v3_auth_protocol: str = "SHA",
    v3_auth_key: str = "",
    v3_priv_protocol: str = "AES",
    v3_priv_key: str = "",
) -> SNMPDeviceInfo:
    info = SNMPDeviceInfo(host=host, community=community)

    if not SNMP_AVAILABLE:
        info.error = "snmpget CLI aracı bulunamadı"
        return info

    ver_args = _build_args(
        snmp_version, community,
        v3_username, v3_auth_protocol, v3_auth_key,
        v3_priv_protocol, v3_priv_key,
    )

    try:
        # 1) Sistem OID'leri
        sys_raw = await _run_snmpget(
            host, list(SYSTEM_OIDS.values()), ver_args
        )

        def _s(oid: str) -> str:
            return sys_raw.get(oid, "").strip()

        def _i(oid: str) -> int:
            return _parse_uptime(_s(oid)) if "sysUpTime" in [
                k for k, v in SYSTEM_OIDS.items() if v == oid
            ] else (int(_s(oid)) if _s(oid).isdigit() else 0)

        info.sys_descr     = _s(SYSTEM_OIDS["sysDescr"])
        info.sys_object_id = _s(SYSTEM_OIDS["sysObjectID"])
        info.sys_name      = _s(SYSTEM_OIDS["sysName"])
        uptime_raw         = _s(SYSTEM_OIDS["sysUpTime"])
        info.uptime_ticks  = _parse_uptime(uptime_raw)

        if not (info.sys_descr or info.sys_name):
            info.error = "Cihaz yanıt vermedi"
            return info

        # 2) Arayüz tablosu — paralel walk
        cols = await asyncio.gather(
            _run_snmpwalk(host, IF_TABLE_OIDS["ifDescr"],       ver_args),
            _run_snmpwalk(host, IF_TABLE_OIDS["ifOperStatus"],  ver_args),
            _run_snmpwalk(host, IF_TABLE_OIDS["ifHCInOctets"],  ver_args),
            _run_snmpwalk(host, IF_TABLE_OIDS["ifHCOutOctets"], ver_args),
            _run_snmpwalk(host, IF_TABLE_OIDS["ifInErrors"],    ver_args),
            _run_snmpwalk(host, IF_TABLE_OIDS["ifOutErrors"],   ver_args),
            _run_snmpwalk(host, IF_TABLE_OIDS["ifInDiscards"],  ver_args),
        )
        descr_col, status_col, hc_in_col, hc_out_col, in_err_col, out_err_col, in_disc_col = cols

        # 64-bit counter yoksa 32-bit fallback
        if not hc_in_col and not hc_out_col:
            hc_in_col, hc_out_col = await asyncio.gather(
                _run_snmpwalk(host, IF_TABLE_OIDS["ifInOctets"],  ver_args),
                _run_snmpwalk(host, IF_TABLE_OIDS["ifOutOctets"], ver_args),
            )

        all_indices = set(descr_col) | set(status_col) | set(hc_in_col) | set(hc_out_col)

        for idx in sorted(all_indices, key=lambda x: int(x) if x.isdigit() else 0):
            hc_in  = int(hc_in_col.get(idx,  "0") or "0")
            hc_out = int(hc_out_col.get(idx, "0") or "0")
            in_bps, out_bps = _calc_bandwidth(host, idx, hc_in, hc_out)

            info.interfaces.append(SNMPInterface(
                index=idx,
                name=descr_col.get(idx, f"if{idx}"),
                oper_status=int(status_col.get(idx, "2") or "2"),
                hc_in_octets=hc_in,
                hc_out_octets=hc_out,
                in_errors=int(in_err_col.get(idx,  "0") or "0"),
                out_errors=int(out_err_col.get(idx, "0") or "0"),
                in_discards=int(in_disc_col.get(idx, "0") or "0"),
                bandwidth_in_bps=in_bps,
                bandwidth_out_bps=out_bps,
            ))

        info.reachable = True
        info.polled_at = datetime.now(timezone.utc)

    except Exception as exc:
        info.error = str(exc)
        info.reachable = False

    return info


def poll_device(
    host: str,
    community: str = "public",
    snmp_version: str = "v2c",
    v3_username: str = "",
    v3_auth_protocol: str = "SHA",
    v3_auth_key: str = "",
    v3_priv_protocol: str = "AES",
    v3_priv_key: str = "",
) -> SNMPDeviceInfo:
    try:
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(poll_device_async(
            host, community, snmp_version,
            v3_username, v3_auth_protocol, v3_auth_key,
            v3_priv_protocol, v3_priv_key,
        ))
    except Exception as exc:
        return SNMPDeviceInfo(host=host, error=str(exc))
