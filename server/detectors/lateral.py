"""
NetGuard — Lateral Movement (Yanal Hareket) Dedektörü

İç ağdan iç ağa SYN paketlerini izler. Bir iç IP'den kısa sürede
birden fazla farklı iç hedefe SSH/SMB/RDP gibi hassas portlarda bağlantı
girişimi olması = yanal hareket göstergesi.

Demo senaryosu:
  Kali → Agent VM SSH erişimi → Agent VM'den iç ağ taraması
  Agent VM (192.168.203.142) → diğer iç IP'lere port 22/445/3389

Gereksinim: tshark kurulu + netguard kullanıcısı wireshark grubunda olmalı.

Eşik: NETGUARD_LATERAL_THRESHOLD (varsayılan: 3 farklı iç hedef IP)
Pencere: NETGUARD_LATERAL_WINDOW saniye (varsayılan: 120)
"""

import logging
import os
import socket
import threading
import time
from collections import defaultdict

from server.detectors.base import BaseDetector
from shared.models import LogCategory, NormalizedLog

logger = logging.getLogger(__name__)

UNIQUE_HOSTS_THRESHOLD = int(os.getenv("NETGUARD_LATERAL_THRESHOLD", "3"))
WINDOW_SECONDS         = int(os.getenv("NETGUARD_LATERAL_WINDOW", "120"))
NETWORK_INTERFACE      = os.getenv("NETGUARD_INTERFACE", "ens33")

# RFC 1918 — iç ağ aralıkları
_PRIVATE_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)

# Yanal harekette kullanılan hassas servis portları
LATERAL_PORTS = frozenset({
    22,    # SSH
    23,    # Telnet
    135,   # MS RPC
    139,   # NetBIOS
    445,   # SMB
    3389,  # RDP
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
})


def _is_private(ip: str) -> bool:
    """IP adresinin RFC 1918 iç ağ aralığında olup olmadığını kontrol eder."""
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


class LateralMovementDetector(BaseDetector):
    """
    İç ağdan iç ağa hassas portlarda SYN paketlerini izler.
    Tek bir iç IP'den birden fazla farklı iç hedefe bağlantı = yanal hareket.

    _history: {src_ip: [(monotonic_ts, dst_ip, dst_port), ...]}
    """

    name = "lateral_movement"

    def __init__(
        self,
        threshold: int = UNIQUE_HOSTS_THRESHOLD,
        window_seconds: int = WINDOW_SECONDS,
    ):
        self._threshold = threshold
        self._window    = window_seconds
        self._history: dict[str, list[tuple[float, str, int]]] = defaultdict(list)
        self._alerted: set[str] = set()
        self._lock = threading.Lock()
        try:
            self.source_host = socket.gethostname()
        except Exception:
            self.source_host = "localhost"
        self._start_sniffer()

    def _start_sniffer(self) -> None:
        try:
            import pyshark  # noqa: F401
        except ImportError:
            logger.warning("pyshark kurulu değil — lateral movement tespiti devre dışı")
            return
        t = threading.Thread(target=self._sniff_loop, daemon=True)
        t.start()
        logger.info(f"Lateral movement sniffer başlatıldı — arayüz: {NETWORK_INTERFACE}")

    def _sniff_loop(self) -> None:
        import pyshark
        capture = pyshark.LiveCapture(
            interface=NETWORK_INTERFACE,
            bpf_filter=(
                "tcp[tcpflags] & (tcp-syn) != 0 "
                "and tcp[tcpflags] & (tcp-ack) == 0"
            ),
            use_json=True,
            include_raw=False,
        )
        try:
            for packet in capture.sniff_continuously():
                try:
                    src_ip   = packet.ip.src
                    dst_ip   = packet.ip.dst
                    dst_port = int(packet.tcp.dstport)
                    if (
                        _is_private(src_ip)
                        and _is_private(dst_ip)
                        and src_ip != dst_ip
                        and dst_port in LATERAL_PORTS
                    ):
                        now = time.monotonic()
                        with self._lock:
                            self._history[src_ip].append((now, dst_ip, dst_port))
                except AttributeError:
                    pass
        except Exception as exc:
            logger.error(f"Lateral movement sniffer durdu: {exc}")

    def detect(self) -> list[NormalizedLog]:
        now    = time.monotonic()
        cutoff = now - self._window

        with self._lock:
            for ip in list(self._history):
                self._history[ip] = [
                    e for e in self._history[ip] if e[0] >= cutoff
                ]
                if not self._history[ip]:
                    del self._history[ip]
                    self._alerted.discard(ip)
            snapshot = {ip: list(entries) for ip, entries in self._history.items()}

        results = []
        for src_ip, entries in snapshot.items():
            unique_hosts = {dst_ip for _, dst_ip, _ in entries}
            if len(unique_hosts) >= self._threshold and src_ip not in self._alerted:
                with self._lock:
                    self._alerted.add(src_ip)
                ports_seen   = sorted({port for _, _, port in entries})
                target_hosts = sorted(unique_hosts)
                log = self._make_log(
                    event_type = "lateral_movement",
                    message    = (
                        f"Yanal hareket tespiti: {src_ip} → "
                        f"{len(unique_hosts)} farklı iç hedef / {self._window}s "
                        f"(eşik: {self._threshold}) | "
                        f"Hedefler: {target_hosts} | Portlar: {ports_seen}"
                    ),
                    category = LogCategory.INTRUSION,
                    severity = "critical",
                    src_ip   = src_ip,
                    tags     = ["lateral_movement", "internal_scan"],
                )
                results.append(log)
                logger.warning(
                    f"YANAL HAREKET: {src_ip} → "
                    f"{len(unique_hosts)} iç hedef / {self._window}s | "
                    f"Portlar: {ports_seen}"
                )

        return results
