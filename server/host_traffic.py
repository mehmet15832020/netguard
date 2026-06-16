"""
NetGuard — Host trafik özeti (B4)

agent/traffic_collector.py (pyshark) kaldırıldı — host'a özel paket yakalama
NSM mimarisinde host-agent sorumluluğu değil, ağ sensörü (Zeek/Suricata)
sorumluluğudur (SANS NSM, Security Onion). Bu modül aynı dashboard panelini
(agents/{id} sayfası "Trafik Özeti") Zeek conn.log + NetFlow kayıtlarından
üretir — pyshark'tan daha güvenilir (sürekli çalışır, 30s'de bir 10s
yakalama değil) ve zaten var olan sensörleri tekrar kullanır.

Not: Zeek conn.log parser'ı (parsers/zeek.py::parse_conn) sadece "ilginç"
bağlantıları (REJ/RSTO/RSTOS0/S0 + 2s+ süren SF) normalized_logs'a yazar —
kısa/normal SF bağlantılar filtrelenir. Bu yüzden total_packets/total_bytes
NetFlow ile zenginleştirilmiş olsa da literal "ağdaki her paket" anlamına
gelmez; güvenlik açısından ilginç + NetFlow'un gördüğü tüm akışların özetidir.
"""

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from shared.models import ProtocolStats, TrafficSummary

TRAFFIC_SOURCE_LABEL = "Zeek + NetFlow"
_TOP_IP_LIMIT = 5


def _row_packet_count(row: dict) -> int:
    """NetFlow satırları extra.packets taşır; Zeek conn satırları taşımaz (1 akış say)."""
    raw_extra = row.get("extra")
    if not raw_extra:
        return 1
    try:
        extra = json.loads(raw_extra) if isinstance(raw_extra, str) else raw_extra
    except (json.JSONDecodeError, TypeError):
        return 1
    packets = extra.get("packets") if isinstance(extra, dict) else None
    return int(packets) if isinstance(packets, (int, float)) and packets > 0 else 1


def build_traffic_summary(
    ip: str, rows: list[dict], window_seconds: float,
) -> TrafficSummary:
    """Verilen IP'ye ait normalized_logs satırlarından (Zeek+NetFlow) TrafficSummary üretir."""
    total_packets = 0
    total_bytes = 0
    protocol_packets: Counter = Counter()
    protocol_bytes: Counter = Counter()
    peers_in: Counter = Counter()   # bu IP'ye bağlanan kaynaklar
    peers_out: Counter = Counter()  # bu IP'nin bağlandığı hedefler
    suspicious = 0

    for row in rows:
        pkt_count = _row_packet_count(row)
        byte_count = int(row.get("network_bytes") or 0)
        protocol = (row.get("network_protocol") or "OTHER").upper()

        total_packets += pkt_count
        total_bytes += byte_count
        protocol_packets[protocol] += pkt_count
        protocol_bytes[protocol] += byte_count

        src = row.get("source_ip")
        dst = row.get("destination_ip")
        if dst == ip and src and src != ip:
            peers_in[src] += 1
        if src == ip and dst and dst != ip:
            peers_out[dst] += 1

        if row.get("severity") in ("warning", "high", "critical"):
            suspicious += 1

    protocols = [
        ProtocolStats(
            protocol=proto,
            packet_count=protocol_packets[proto],
            byte_count=protocol_bytes[proto],
            percentage=(protocol_bytes[proto] / total_bytes * 100) if total_bytes else 0.0,
        )
        for proto in protocol_packets
    ]
    protocols.sort(key=lambda p: p.byte_count, reverse=True)

    return TrafficSummary(
        interface=TRAFFIC_SOURCE_LABEL,
        duration_sec=window_seconds,
        total_packets=total_packets,
        total_bytes=total_bytes,
        protocols=protocols,
        top_src_ips=[ip for ip, _ in peers_in.most_common(_TOP_IP_LIMIT)],
        top_dst_ips=[ip for ip, _ in peers_out.most_common(_TOP_IP_LIMIT)],
        captured_at=datetime.now(timezone.utc),
        suspicious_packet_count=suspicious,
    )
