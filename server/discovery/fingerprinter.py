"""
NetGuard — Port/Banner Fingerprinter

Aktif IP'lere yaygın portları dener, banner okur, vendor tahmin eder.
SNMP varsa sysDescr + sysName çeker.
"""

import asyncio
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Taranacak portlar ve servis adları
COMMON_PORTS: dict[int, str] = {
    22:   "ssh",
    23:   "telnet",
    80:   "http",
    443:  "https",
    161:  "snmp",
    445:  "smb",
    3389: "rdp",
    8080: "http-alt",
    8443: "https-alt",
}

_BANNER_TIMEOUT = 2.0   # saniye
_TCP_CONNECT_TIMEOUT = 1.5

# OUI → vendor eşleşmesi (MAC'in ilk 3 byte'ı)
# Lokal minimal tablo — tam liste Faz 7'de genişletilir
OUI_TABLE: dict[str, str] = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1a:a0": "Dell",
    "00:1e:c9": "Dell",
    "3c:d9:2b": "Hewlett Packard",
    "00:1b:21": "Intel",
    "00:14:22": "Dell",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:50:ba": "D-Link",
    "00:1c:c0": "D-Link",
    "00:17:9a": "D-Link",
    "00:18:e7": "Cisco",
    "00:1a:a1": "Cisco",
    "00:1f:6c": "Cisco",
    "c8:4c:75": "Cisco",
    "00:0d:29": "Cisco",
    "00:e0:4c": "Realtek",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
}


def _lookup_vendor(mac: Optional[str]) -> str:
    if not mac:
        return ""
    prefix = mac.lower()[:8]
    return OUI_TABLE.get(prefix, "")


async def _grab_banner(host: str, port: int, timeout: float = _BANNER_TIMEOUT) -> str:
    """
    TCP bağlantısı açar, banner okur (ilk 512 byte).
    HTTP için HEAD isteği gönderir.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=_TCP_CONNECT_TIMEOUT,
        )
    except Exception:
        return ""

    banner = ""
    try:
        if port in (80, 8080):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            await writer.drain()
        elif port in (443, 8443):
            # TLS olmadan sadece bağlantı — banner yok ama port açık bilgisi yeterli
            writer.close()
            return "tls"

        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        banner = data.decode(errors="replace").strip()
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return banner[:256]


def _classify_banner(port: int, banner: str) -> dict:
    """Banner'dan servis ve sürüm bilgisi çıkar."""
    info: dict = {"service": COMMON_PORTS.get(port, f"port-{port}"), "version": "", "vendor": ""}

    if not banner:
        return info

    b = banner.lower()

    if port == 22 or "ssh" in b:
        # "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        m = re.search(r"ssh-[\d.]+-(\S+)", banner, re.I)
        if m:
            info["version"] = m.group(1)
        if "openssh" in b:
            info["vendor"] = "OpenSSH"

    elif port in (80, 8080) and "server:" in b:
        m = re.search(r"server:\s*(.+)", banner, re.I)
        if m:
            server = m.group(1).strip()
            info["version"] = server
            if "nginx" in b:
                info["vendor"] = "nginx"
            elif "apache" in b:
                info["vendor"] = "Apache"
            elif "iis" in b:
                info["vendor"] = "Microsoft IIS"

    elif port == 23:
        info["service"] = "telnet"

    return info


async def _snmp_fingerprint(host: str, community: str = "public") -> dict:
    """SNMP GET ile sysDescr + sysName çeker."""
    try:
        from server.snmp_collector import _snmp_get, SYSTEM_OIDS, SNMP_AVAILABLE
        if not SNMP_AVAILABLE:
            return {}
        sys_descr, sys_name = await asyncio.gather(
            _snmp_get(host, community, SYSTEM_OIDS["sysDescr"]),
            _snmp_get(host, community, SYSTEM_OIDS["sysName"]),
            return_exceptions=True,
        )
        result = {}
        if sys_descr and not isinstance(sys_descr, Exception):
            result["sys_descr"] = str(sys_descr)
        if sys_name and not isinstance(sys_name, Exception):
            result["sys_name"] = str(sys_name)
        return result
    except Exception:
        return {}


async def fingerprint(host: str, mac: Optional[str] = None) -> dict:
    """
    Tek bir IP'yi tam olarak tarar.
    Döndürür: {ip, open_ports, services, vendor, sys_descr, sys_name, os_hint}
    """
    result: dict = {
        "ip": host,
        "open_ports": [],
        "services": {},
        "vendor": _lookup_vendor(mac),
        "mac": mac or "",
        "sys_descr": "",
        "sys_name": "",
        "os_hint": "",
    }

    # TCP portlarını paralel tara
    port_list = [p for p in COMMON_PORTS if p != 161]  # SNMP ayrı
    banner_tasks = [_grab_banner(host, p) for p in port_list]
    banners = await asyncio.gather(*banner_tasks, return_exceptions=True)

    for port, banner in zip(port_list, banners):
        if isinstance(banner, Exception) or banner is None:
            continue
        if banner != "":
            result["open_ports"].append(port)
            result["services"][port] = _classify_banner(port, banner)

    # SNMP varsa ek bilgi al
    if 161 not in result["open_ports"]:
        from server.uptime_checker import tcp_check
        snmp_check = await tcp_check(host, 161, timeout=1.0)
        if snmp_check["reachable"]:
            result["open_ports"].append(161)

    if 161 in result["open_ports"]:
        snmp_data = await _snmp_fingerprint(host)
        result.update(snmp_data)
        result["services"][161] = {"service": "snmp", "version": "", "vendor": ""}

    # OS tahmini — banner veya SNMP'den
    descr = result.get("sys_descr", "").lower()
    if "linux" in descr:
        result["os_hint"] = "Linux"
    elif "windows" in descr:
        result["os_hint"] = "Windows"
    elif "cisco" in descr or "ios" in descr:
        result["os_hint"] = "Cisco IOS"
        if not result["vendor"]:
            result["vendor"] = "Cisco"
    elif "ubuntu" in descr or "debian" in descr:
        result["os_hint"] = "Linux"
    elif any(b for b in banners if isinstance(b, str) and "openssh" in b.lower()):
        result["os_hint"] = "Linux"

    return result
