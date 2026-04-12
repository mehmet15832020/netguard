"""
NetGuard — ARP Spoofing Dedektörü

/proc/net/arp dosyasını periyodik okuyarak IP→MAC eşlemesini takip eder.
İki anormal durum tespit edilir:
  1. Bir IP'nin MAC adresi değişirse (ARP cache poisoning)
  2. Aynı MAC adresi birden fazla IP'ye sahipse (MITM)

Tespit başına "arp_spoof_attempt" NormalizedLog üretir.
Tek bir tespit bile kritik — korelasyon kuralında threshold=1 olmalı.
"""

import logging
import os
import socket
from pathlib import Path
from typing import Optional

from server.detectors.base import BaseDetector
from shared.models import LogCategory, NormalizedLog

logger = logging.getLogger(__name__)

ARP_TABLE_PATH = os.getenv("NETGUARD_ARP_TABLE", "/proc/net/arp")


def _parse_arp_table(path: str) -> dict[str, str]:
    """
    /proc/net/arp dosyasını parse et.
    Döner: {ip: mac} — sadece tamamlanmış (Flags=0x2) kayıtlar.
    """
    result: dict[str, str] = {}
    try:
        content = Path(path).read_text()
    except OSError as exc:
        logger.warning(f"ARP tablosu okunamadı: {exc}")
        return result

    for line in content.splitlines()[1:]:   # başlık satırını atla
        parts = line.split()
        if len(parts) < 4:
            continue
        ip_addr  = parts[0]
        flags    = parts[2]
        hw_addr  = parts[3]

        if flags == "0x0" or hw_addr == "00:00:00:00:00:00":
            continue   # eksik kayıt

        result[ip_addr] = hw_addr.lower()

    return result


class ARPSpoofDetector(BaseDetector):
    """
    ARP tablosunu izleyerek IP-MAC eşleme değişikliklerini tespit eder.
    """

    name = "arp_spoof"

    def __init__(self, arp_path: str = ARP_TABLE_PATH):
        self._arp_path  = arp_path
        self._known: dict[str, str] = {}  # {ip: mac} — öğrenilen eşlemeler
        try:
            self.source_host = socket.gethostname()
        except Exception:
            self.source_host = "localhost"

    def detect(self) -> list[NormalizedLog]:
        current = _parse_arp_table(self._arp_path)
        results = []

        # 1. IP→MAC değişimi kontrolü
        for ip, mac in current.items():
            if ip in self._known and self._known[ip] != mac:
                old_mac = self._known[ip]
                log = self._make_log(
                    event_type = "arp_spoof_attempt",
                    message    = (
                        f"ARP spoofing tespiti: {ip} için MAC değişti "
                        f"{old_mac} → {mac}"
                    ),
                    category   = LogCategory.NETWORK,
                    severity   = "critical",
                    src_ip     = ip,
                    tags       = ["arp_spoof", "mitm", "network_attack"],
                )
                results.append(log)
                logger.critical(f"ARP spoof: {ip} MAC değişti {old_mac} → {mac}")

        # 2. Aynı MAC'e sahip birden fazla IP kontrolü (MITM göstergesi)
        mac_to_ips: dict[str, list[str]] = {}
        for ip, mac in current.items():
            mac_to_ips.setdefault(mac, []).append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                log = self._make_log(
                    event_type = "arp_spoof_attempt",
                    message    = (
                        f"ARP anomalisi: {mac} MAC adresi birden fazla IP'de: "
                        f"{', '.join(ips)}"
                    ),
                    category   = LogCategory.NETWORK,
                    severity   = "critical",
                    tags       = ["arp_spoof", "duplicate_mac", "network_attack"],
                )
                results.append(log)
                logger.critical(f"ARP anomali: {mac} → {ips}")

        # Bilinen eşlemeleri güncelle
        self._known.update(current)
        return results
