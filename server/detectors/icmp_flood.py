"""
NetGuard — ICMP Flood Dedektörü

/proc/net/snmp dosyasından ICMP istatistiklerini okur.
İki ardışık okuma arasındaki delta'dan saniyedeki paket hızını hesaplar.
Hız ICMP_RATE_THRESHOLD'u aşarsa "icmp_flood_attempt" NormalizedLog üretir.

Eşik: NETGUARD_ICMP_THRESHOLD env değişkeniyle değiştirilebilir (varsayılan: 100 paket/s)
"""

import logging
import os
import socket
import time
from pathlib import Path
from typing import Optional

from server.detectors.base import BaseDetector
from shared.models import LogCategory, NormalizedLog

logger = logging.getLogger(__name__)

SNMP_PATH          = os.getenv("NETGUARD_SNMP_PATH", "/proc/net/snmp")
ICMP_RATE_THRESHOLD = int(os.getenv("NETGUARD_ICMP_THRESHOLD", "100"))  # paket/saniye


def _read_icmp_in_msgs(path: str) -> Optional[int]:
    """
    /proc/net/snmp'den toplam gelen ICMP mesaj sayısını oku.
    Başarısız olursa None döner.
    """
    try:
        content = Path(path).read_text()
    except OSError as exc:
        logger.warning(f"SNMP dosyası okunamadı: {exc}")
        return None

    lines = content.splitlines()
    header_line: Optional[str] = None
    value_line:  Optional[str] = None

    for i, line in enumerate(lines):
        if line.startswith("Icmp:") and header_line is None:
            header_line = line
        elif line.startswith("Icmp:") and header_line is not None:
            value_line = line
            break

    if not header_line or not value_line:
        return None

    headers = header_line.split()
    values  = value_line.split()

    try:
        idx = headers.index("InMsgs")
        return int(values[idx])
    except (ValueError, IndexError):
        return None


class ICMPFloodDetector(BaseDetector):
    """
    ICMP paket hızını izleyerek flood saldırısını tespit eder.
    """

    name = "icmp_flood"

    def __init__(
        self,
        snmp_path: str = SNMP_PATH,
        threshold: int = ICMP_RATE_THRESHOLD,
    ):
        self._snmp_path   = snmp_path
        self._threshold   = threshold
        self._prev_count: Optional[int] = None
        self._prev_time:  Optional[float] = None
        try:
            self.source_host = socket.gethostname()
        except Exception:
            self.source_host = "localhost"

    def detect(self) -> list[NormalizedLog]:
        current_count = _read_icmp_in_msgs(self._snmp_path)
        current_time  = time.monotonic()

        if current_count is None:
            return []

        results = []

        if self._prev_count is not None and self._prev_time is not None:
            elapsed = current_time - self._prev_time
            if elapsed > 0:
                delta = current_count - self._prev_count
                rate  = delta / elapsed   # paket/saniye

                if rate >= self._threshold:
                    log = self._make_log(
                        event_type = "icmp_flood_attempt",
                        message    = (
                            f"ICMP flood tespiti: {rate:.1f} paket/s "
                            f"(eşik: {self._threshold} paket/s)"
                        ),
                        category   = LogCategory.NETWORK,
                        severity   = "critical",
                        tags       = ["icmp_flood", "dos_attack", "network_attack"],
                    )
                    results.append(log)
                    logger.critical(f"ICMP flood: {rate:.1f} pkt/s — eşik: {self._threshold}")

        self._prev_count = current_count
        self._prev_time  = current_time
        return results
