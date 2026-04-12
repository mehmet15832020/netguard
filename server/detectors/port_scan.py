"""
NetGuard — Port Tarama Dedektörü

Aynı uzak IP'den kısa sürede farklı yerel portlara gelen bağlantıları sayar.
Eşik aşılırsa "port_scan_attempt" NormalizedLog üretir.

Tespit mantığı:
  - psutil ile anlık bağlantılar alınır
  - Her uzak IP için kaç farklı yerel porta bağlandığı sayılır
  - Sayı UNIQUE_PORTS_THRESHOLD'u aşarsa → şüpheli

Eşik: NETGUARD_PORTSCAN_THRESHOLD env değişkeniyle değiştirilebilir (varsayılan: 10)
"""

import logging
import os
import socket
from collections import defaultdict

import psutil

from server.detectors.base import BaseDetector
from shared.models import LogCategory, NormalizedLog

logger = logging.getLogger(__name__)

UNIQUE_PORTS_THRESHOLD = int(os.getenv("NETGUARD_PORTSCAN_THRESHOLD", "10"))

# Görmezden gelinecek loopback ve link-local adresler
_IGNORED_PREFIXES = ("127.", "::1", "169.254.")


def _is_ignored(ip: str) -> bool:
    return any(ip.startswith(p) for p in _IGNORED_PREFIXES)


class PortScanDetector(BaseDetector):
    """
    Aktif ağ bağlantılarını analiz ederek port tarama girişimini tespit eder.
    """

    name = "port_scan"

    def __init__(self, threshold: int = UNIQUE_PORTS_THRESHOLD):
        self._threshold = threshold
        try:
            self.source_host = socket.gethostname()
        except Exception:
            self.source_host = "localhost"

    def _get_connections(self) -> list:
        """psutil ile aktif bağlantıları al. Hata durumunda boş liste döner."""
        try:
            return psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as exc:
            logger.warning(f"Port tarama: bağlantı listesi alınamadı: {exc}")
            return []

    def detect(self) -> list[NormalizedLog]:
        connections = self._get_connections()
        if not connections:
            return []

        # uzak_ip → {yerel_port_1, yerel_port_2, ...}
        remote_to_ports: dict[str, set[int]] = defaultdict(set)

        for conn in connections:
            if not conn.raddr or not conn.laddr:
                continue
            remote_ip = conn.raddr.ip
            local_port = conn.laddr.port
            if not remote_ip or _is_ignored(remote_ip):
                continue
            remote_to_ports[remote_ip].add(local_port)

        results = []
        for remote_ip, ports in remote_to_ports.items():
            if len(ports) >= self._threshold:
                sorted_ports = sorted(ports)
                log = self._make_log(
                    event_type = "port_scan_attempt",
                    message    = (
                        f"Port tarama tespiti: {remote_ip} → "
                        f"{len(ports)} farklı port "
                        f"(eşik: {self._threshold}) | "
                        f"Portlar: {sorted_ports[:10]}{'...' if len(sorted_ports) > 10 else ''}"
                    ),
                    category   = LogCategory.NETWORK,
                    severity   = "warning",
                    src_ip     = remote_ip,
                    tags       = ["port_scan", "network_attack"],
                )
                results.append(log)
                logger.warning(f"Port tarama: {remote_ip} — {len(ports)} port")

        return results
