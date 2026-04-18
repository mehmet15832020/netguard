"""
NetGuard — Topology Builder

L2/L3 topoloji keşfi:
  1. devices tablosundan tüm bilinen cihazları node olarak yükle
  2. SNMP'li cihazlardan ARP tablosunu walk et → IP↔MAC eşlemesi → kenar
  3. CDP/LLDP varsa komşu bilgisi → kenar
  4. Subnet çıkarımı (fallback) → aynı /24'teki cihazlar arasında zayıf bağlantı
"""

import asyncio
import logging
from ipaddress import ip_address, ip_network, IPv4Address

logger = logging.getLogger(__name__)

# SNMP OID'leri
ARP_TABLE_OID  = "1.3.6.1.2.1.4.22.1.2"   # ipNetToMediaPhysAddress (MAC)
ARP_ADDR_OID   = "1.3.6.1.2.1.4.22.1.3"   # ipNetToMediaNetAddress  (IP)
LLDP_REM_IP    = "1.0.8802.1.1.2.1.4.2.1.5"  # lldpRemManAddrIfId
LLDP_REM_NAME  = "1.0.8802.1.1.2.1.4.1.1.9"  # lldpRemSysName

_LAYER_HINTS = {
    "snmp": 3,
    "agent": 2,
    "discovered": 3,
    "hybrid": 2,
}


async def _walk_arp(host: str, community: str) -> list[tuple[str, str]]:
    """
    ARP tablosunu walk et.
    Döndürür: [(ip, mac_hex), ...]
    """
    try:
        from server.snmp_collector import _walk_column, SNMP_AVAILABLE
        if not SNMP_AVAILABLE:
            return []

        from pysnmp.hlapi.asyncio import (
            SnmpEngine, CommunityData, UdpTransportTarget,
        )
        transport = await UdpTransportTarget.create((host, 161), timeout=2, retries=1)
        engine = SnmpEngine()
        community_data = CommunityData(community, mpModel=1)

        mac_col, ip_col = await asyncio.gather(
            _walk_column(engine, community_data, transport, ARP_TABLE_OID),
            _walk_column(engine, community_data, transport, ARP_ADDR_OID),
            return_exceptions=True,
        )

        if isinstance(mac_col, Exception) or isinstance(ip_col, Exception):
            return []

        results = []
        for idx, mac_raw in mac_col.items():
            ip_val = ip_col.get(idx)
            if ip_val and mac_raw:
                results.append((str(ip_val), mac_raw.lower()))
        return results
    except Exception as exc:
        logger.debug(f"ARP walk hatası ({host}): {exc}")
        return []


async def _walk_lldp(host: str, community: str) -> list[str]:
    """
    LLDP komşu IP adreslerini walk et.
    Döndürür: [neighbor_ip, ...]
    """
    try:
        from server.snmp_collector import _walk_column, SNMP_AVAILABLE
        if not SNMP_AVAILABLE:
            return []

        from pysnmp.hlapi.asyncio import (
            SnmpEngine, CommunityData, UdpTransportTarget,
        )
        transport = await UdpTransportTarget.create((host, 161), timeout=2, retries=1)
        engine = SnmpEngine()
        community_data = CommunityData(community, mpModel=1)

        ip_col = await _walk_column(engine, community_data, transport, LLDP_REM_IP)
        if not ip_col:
            return []
        return [str(v) for v in ip_col.values() if v]
    except Exception as exc:
        logger.debug(f"LLDP walk hatası ({host}): {exc}")
        return []


def _subnet_edges(devices: list[dict]) -> list[tuple[str, str]]:
    """
    Aynı /24 subnet'indeki cihazlar arasında zayıf kenar üret.
    Gerçek L2 bağlantı bilgisi yoksa fallback olarak kullanılır.
    """
    edges = []
    ip_to_id: dict[str, str] = {}
    for dev in devices:
        ip = dev.get("ip", "")
        if ip and _valid_ip(ip):
            ip_to_id[ip] = dev["device_id"]

    ips = list(ip_to_id.keys())
    grouped: dict[str, list[str]] = {}
    for ip in ips:
        try:
            net = str(ip_network(f"{ip}/24", strict=False).network_address)
            grouped.setdefault(net, []).append(ip)
        except ValueError:
            pass

    for net_ips in grouped.values():
        if len(net_ips) < 2:
            continue
        anchor = net_ips[0]
        for peer in net_ips[1:]:
            a, b = sorted([ip_to_id[anchor], ip_to_id[peer]])
            edges.append((a, b))

    return edges


def _valid_ip(s: str) -> bool:
    try:
        ip_address(s)
        return True
    except ValueError:
        return False


async def build_topology() -> dict:
    """
    Tüm topolojiyi yeniden oluştur ve DB'ye kaydet.
    Döndürür: {"nodes": N, "edges": E} özet sayıları.
    """
    from server.database import db

    db.clear_topology()
    devices = db.get_devices()

    # 1. Tüm bilinen cihazları node olarak ekle
    for dev in devices:
        db.upsert_topology_node(
            device_id=dev["device_id"],
            name=dev.get("name") or dev["device_id"],
            ip=dev.get("ip", ""),
            device_type=dev.get("type", "unknown"),
            vendor=dev.get("vendor", ""),
            os_info=dev.get("os_info", ""),
            layer=_LAYER_HINTS.get(dev.get("type", ""), 3),
        )

    # 2. SNMP'li cihazlardan ARP + LLDP walk
    snmp_devices = [d for d in devices if d.get("type") == "snmp" and d.get("ip")]
    ip_to_id: dict[str, str] = {
        d["ip"]: d["device_id"] for d in devices if d.get("ip") and _valid_ip(d["ip"])
    }

    arp_edge_count = 0
    lldp_edge_count = 0

    for dev in snmp_devices:
        host = dev["ip"]
        community = dev.get("snmp_community", "public") or "public"

        arp_entries, lldp_neighbors = await asyncio.gather(
            _walk_arp(host, community),
            _walk_lldp(host, community),
            return_exceptions=True,
        )

        if isinstance(arp_entries, list):
            for peer_ip, _mac in arp_entries:
                if peer_ip in ip_to_id and peer_ip != host:
                    db.upsert_topology_edge(
                        src_id=dev["device_id"],
                        dst_id=ip_to_id[peer_ip],
                        link_type="ip",
                        discovered="arp",
                    )
                    arp_edge_count += 1

        if isinstance(lldp_neighbors, list):
            for neighbor_ip in lldp_neighbors:
                if neighbor_ip in ip_to_id and neighbor_ip != host:
                    db.upsert_topology_edge(
                        src_id=dev["device_id"],
                        dst_id=ip_to_id[neighbor_ip],
                        link_type="ethernet",
                        discovered="lldp",
                    )
                    lldp_edge_count += 1

    # 3. Subnet fallback — ARP/LLDP'den kenar bulunamadıysa
    graph = db.get_topology_graph()
    if not graph["edges"]:
        for src_id, dst_id in _subnet_edges(devices):
            db.upsert_topology_edge(src_id, dst_id, link_type="ip", discovered="subnet")

    graph = db.get_topology_graph()
    logger.info(
        f"Topoloji güncellendi: {len(graph['nodes'])} node, "
        f"{len(graph['edges'])} edge "
        f"(arp={arp_edge_count}, lldp={lldp_edge_count})"
    )
    return {"nodes": len(graph["nodes"]), "edges": len(graph["edges"])}
