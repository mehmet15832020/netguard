"""
NetGuard — DNS Anomali Dedektörü

/proc/net/udp dosyasını okuyarak port 53'e yönelik UDP bağlantılarını izler.
Kısa sürede yüksek sayıda DNS sorgusu yapan process/IP tespit edilirse
"dns_query_burst" NormalizedLog üretir.

Alternatif olarak psutil ile de aynı bilgi alınabilir.

Eşik: NETGUARD_DNS_THRESHOLD env değişkeniyle değiştirilebilir (varsayılan: 30 sorgu/kontrol)
"""

import logging
import os
import socket
from collections import defaultdict
from pathlib import Path

import psutil

from server.detectors.base import BaseDetector
from shared.models import LogCategory, NormalizedLog

logger = logging.getLogger(__name__)

DNS_QUERY_THRESHOLD = int(os.getenv("NETGUARD_DNS_THRESHOLD", "30"))
DNS_PORT = 53


def _hex_to_ip(hex_addr: str) -> str:
    """Little-endian hex adresini dotted notation'a çevir (IPv4)."""
    try:
        addr_int = int(hex_addr, 16)
        return socket.inet_ntoa(addr_int.to_bytes(4, "little"))
    except Exception:
        return hex_addr


def _read_dns_connections_proc() -> dict[str, int]:
    """
    /proc/net/udp'den port 53 hedefli bağlantıları oku.
    Döner: {kaynak_ip: bağlantı_sayısı}
    """
    result: dict[str, int] = defaultdict(int)
    udp_path = "/proc/net/udp"
    try:
        content = Path(udp_path).read_text()
    except OSError:
        return result

    # DNS_PORT'un hex karşılığı (big-endian)
    dns_port_hex = f"{DNS_PORT:04X}"

    for line in content.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        # rem_address alanı: hex_ip:hex_port
        rem = parts[2]
        if ":" not in rem:
            continue
        _rem_ip_hex, rem_port_hex = rem.split(":")
        if rem_port_hex.upper() == dns_port_hex:
            local = parts[1]
            src_ip_hex = local.split(":")[0]
            src_ip = _hex_to_ip(src_ip_hex)
            result[src_ip] += 1

    return result


class DNSAnomalyDetector(BaseDetector):
    """
    DNS sorgu yoğunluğunu izleyerek DNS flood / tünel tespiti yapar.
    """

    name = "dns_anomaly"

    def __init__(self, threshold: int = DNS_QUERY_THRESHOLD):
        self._threshold = threshold
        try:
            self.source_host = socket.gethostname()
        except Exception:
            self.source_host = "localhost"

    def _get_dns_counts(self) -> dict[str, int]:
        """
        psutil üzerinden UDP port 53 bağlantılarını say.
        /proc/net/udp'ye fallback yapar.
        """
        counts: dict[str, int] = defaultdict(int)
        try:
            for conn in psutil.net_connections(kind="udp"):
                if conn.raddr and conn.raddr.port == DNS_PORT:
                    src_ip = conn.laddr.ip if conn.laddr else "unknown"
                    counts[src_ip] += 1
        except (psutil.AccessDenied, PermissionError):
            return _read_dns_connections_proc()
        return counts

    def detect(self) -> list[NormalizedLog]:
        counts = self._get_dns_counts()
        results = []

        for src_ip, count in counts.items():
            if count >= self._threshold:
                log = self._make_log(
                    event_type = "dns_query_burst",
                    message    = (
                        f"DNS anomalisi: {src_ip} → {count} DNS sorgusu "
                        f"(eşik: {self._threshold})"
                    ),
                    category   = LogCategory.NETWORK,
                    severity   = "warning",
                    src_ip     = src_ip,
                    dst_port   = DNS_PORT,
                    tags       = ["dns_anomaly", "network_attack"],
                )
                results.append(log)
                logger.warning(f"DNS anomalisi: {src_ip} — {count} sorgu")

        return results
