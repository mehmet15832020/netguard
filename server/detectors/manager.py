"""
NetGuard — Dedektör Yöneticisi

Tüm dedektörleri tek çatı altında çalıştırır.
Her detect() çağrısında üretilen NormalizedLog'ları DB'ye yazar.
main.py'deki periyodik döngü bu sınıfı kullanır.
"""

import logging
import uuid
from datetime import datetime, timezone

from server.database import db
from server.detectors.arp_spoof import ARPSpoofDetector
from server.detectors.dns_anomaly import DNSAnomalyDetector
from server.detectors.icmp_flood import ICMPFloodDetector
from server.detectors.port_scan import PortScanDetector
from shared.models import NormalizedLog, SecurityEvent, SecurityEventType

logger = logging.getLogger(__name__)


class DetectorManager:
    """Tüm dedektörleri yönetir ve çalıştırır."""

    def __init__(self):
        self._detectors = [
            PortScanDetector(),
            ARPSpoofDetector(),
            ICMPFloodDetector(),
            DNSAnomalyDetector(),
        ]

    def run_all(self) -> list[NormalizedLog]:
        """
        Tüm dedektörleri sırayla çalıştır.
        Üretilen NormalizedLog'ları DB'ye yaz ve listesini döner.
        """
        all_logs: list[NormalizedLog] = []

        for detector in self._detectors:
            try:
                logs = detector.detect()
                for log in logs:
                    db.save_normalized_log(log)
                    _save_as_security_event(log)
                if logs:
                    logger.info(f"[{detector.name}] {len(logs)} olay tespit edildi")
                all_logs.extend(logs)
            except Exception as exc:
                logger.error(f"[{detector.name}] hata: {exc}")

        return all_logs

    @property
    def detector_names(self) -> list[str]:
        return [d.name for d in self._detectors]


_EVENT_TYPE_MAP = {
    "port_scan_attempt": SecurityEventType.PORT_SCAN,
    "arp_spoof":         SecurityEventType.ARP_SPOOF,
    "icmp_flood":        SecurityEventType.ICMP_FLOOD,
    "dns_anomaly":       SecurityEventType.DNS_ANOMALY,
}


def _save_as_security_event(log: NormalizedLog) -> None:
    event_type = _EVENT_TYPE_MAP.get(log.event_type)
    if event_type is None:
        return
    event = SecurityEvent(
        event_id   = str(uuid.uuid4()),
        agent_id   = log.source_host,
        hostname   = log.source_host,
        event_type = event_type,
        severity   = log.severity,
        source_ip  = log.src_ip,
        message    = log.message,
        raw_data   = log.message,
        occurred_at = log.timestamp,
    )
    db.save_security_event(event)


# Global instance
detector_manager = DetectorManager()
