"""
NetGuard — Port Tarama Dedektörü

SYN paketlerini pyshark ile yakalar. Aynı kaynak IP'den kısa sürede
farklı hedef portlara gelen SYN sayısı eşiği aşarsa alarm üretir.

Neden SYN paketi?
  - nmap -sS (SYN tarama): TCP 3-way handshake tamamlamaz, psutil göremez.
  - nmap -sT (connect tarama): bağlantılar çok kısa sürer, psutil kaçırır.
  - SYN paketini yakalamak her iki durumu da güvenilir şekilde tespit eder.

Gereksinim: tshark kurulu + netguard kullanıcısı wireshark grubunda olmalı.
  sudo apt install tshark
  sudo usermod -aG wireshark netguard

Eşik: NETGUARD_PORTSCAN_THRESHOLD (varsayılan: 15)
Pencere: NETGUARD_PORTSCAN_WINDOW saniye (varsayılan: 60)
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

UNIQUE_PORTS_THRESHOLD = int(os.getenv("NETGUARD_PORTSCAN_THRESHOLD", "15"))
WINDOW_SECONDS         = int(os.getenv("NETGUARD_PORTSCAN_WINDOW", "60"))
NETWORK_INTERFACE      = os.getenv("NETGUARD_INTERFACE", "ens33")


class PortScanDetector(BaseDetector):
    """
    Arka planda tshark ile SYN paketlerini dinler.
    detect() çağrıldığında biriken veriyi değerlendirir.

    _history: {src_ip: [(timestamp, dst_port), ...]}
    """

    name = "port_scan"

    def __init__(
        self,
        threshold: int = UNIQUE_PORTS_THRESHOLD,
        window_seconds: int = WINDOW_SECONDS,
    ):
        self._threshold = threshold
        self._window    = window_seconds
        self._history: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self._alerted: set[str] = set()
        self._lock = threading.Lock()
        try:
            self.source_host = socket.gethostname()
        except Exception:
            self.source_host = "localhost"
        self._start_sniffer()

    def _start_sniffer(self) -> None:
        """Arka planda tshark ile SYN paketlerini yakala."""
        try:
            import pyshark
        except ImportError:
            logger.warning("pyshark kurulu değil — port tarama tespiti devre dışı")
            return

        t = threading.Thread(target=self._sniff_loop, daemon=True)
        t.start()
        logger.info(f"Port tarama sniffer başlatıldı — arayüz: {NETWORK_INTERFACE}")

    def _sniff_loop(self) -> None:
        """Sürekli çalışan sniffer döngüsü — sadece TCP SYN paketleri."""
        import pyshark

        # tcp.flags.syn==1 AND tcp.flags.ack==0 → sadece ilk SYN (SYN-ACK değil)
        capture = pyshark.LiveCapture(
            interface=NETWORK_INTERFACE,
            bpf_filter="tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0",
            use_json=True,
            include_raw=False,
        )

        try:
            for packet in capture.sniff_continuously():
                try:
                    src_ip   = packet.ip.src
                    dst_port = int(packet.tcp.dstport)
                    now      = time.monotonic()
                    with self._lock:
                        self._history[src_ip].append((now, dst_port))
                except AttributeError:
                    pass  # IP veya TCP katmanı yoksa atla
        except Exception as exc:
            logger.error(f"Port tarama sniffer durdu: {exc}")

    def detect(self) -> list[NormalizedLog]:
        now    = time.monotonic()
        cutoff = now - self._window

        with self._lock:
            # Eski girişleri temizle
            for ip in list(self._history):
                self._history[ip] = [
                    (t, p) for t, p in self._history[ip] if t >= cutoff
                ]
                if not self._history[ip]:
                    del self._history[ip]
                    self._alerted.discard(ip)

            snapshot = {ip: list(entries) for ip, entries in self._history.items()}

        results = []
        for src_ip, entries in snapshot.items():
            unique_ports = {p for _, p in entries}
            if len(unique_ports) >= self._threshold and src_ip not in self._alerted:
                with self._lock:
                    self._alerted.add(src_ip)
                sorted_ports = sorted(unique_ports)
                log = self._make_log(
                    event_type = "port_scan_attempt",
                    message    = (
                        f"Port tarama tespiti: {src_ip} → "
                        f"{len(unique_ports)} farklı port / {self._window}s "
                        f"(eşik: {self._threshold}) | "
                        f"Portlar: {sorted_ports[:10]}"
                        f"{'...' if len(sorted_ports) > 10 else ''}"
                    ),
                    category = LogCategory.NETWORK,
                    severity = "warning",
                    src_ip   = src_ip,
                    tags     = ["port_scan", "network_attack"],
                )
                results.append(log)
                logger.warning(
                    f"PORT TARAMA: {src_ip} — {len(unique_ports)} port / {self._window}s"
                )

        return results
