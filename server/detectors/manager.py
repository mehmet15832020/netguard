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
from server.detectors.beaconing import BeaconingDetector
from server.detectors.dns_anomaly import DNSAnomalyDetector
from server.detectors.icmp_flood import ICMPFloodDetector
from server.detectors.lateral import LateralMovementDetector
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
            LateralMovementDetector(),
        ]
        self._beaconing = BeaconingDetector()

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

    def run_beaconing(self) -> list[NormalizedLog]:
        """
        C2 beaconing tespitini çalıştır (MITRE ATT&CK T1071 / TA0011).

        run_all()'dan ayrı tutulur çünkü:
        - RITA önerisi: IAT istatistik analizi için 5 dakikalık örnekleme yeterli
        - Doğrudan kill chain feed gerektirir (60s correlator gecikmesi kabul edilemez)
        """
        from server.attack_chain import attack_chain_tracker, chain_trigger_to_correlated_event

        logs: list[NormalizedLog] = []
        try:
            logs = self._beaconing.detect()
            for log in logs:
                db.save_normalized_log(log)
                _save_as_security_event(log)
                if log.source_ip:
                    try:
                        trigger = attack_chain_tracker.record(
                            source_ip=log.source_ip,
                            event_action=log.event_action,
                            occurred_at=log.timestamp,
                        )
                        if trigger:
                            chain_trigger_to_correlated_event(trigger, db_save=True)
                    except Exception as exc:
                        logger.warning("Beaconing kill chain kaydı başarısız: %s", exc)
            if logs:
                logger.warning("[beaconing] %d C2 beacon tespiti", len(logs))
        except Exception as exc:
            logger.error("[beaconing] hata: %s", exc)
        return logs

    @property
    def detector_names(self) -> list[str]:
        return [d.name for d in self._detectors] + [self._beaconing.name]


_EVENT_TYPE_MAP = {
    "port_scan_attempt": SecurityEventType.PORT_SCAN,
    "arp_spoof":         SecurityEventType.ARP_SPOOF,
    "icmp_flood":        SecurityEventType.ICMP_FLOOD,
    "dns_anomaly":       SecurityEventType.DNS_ANOMALY,
    "lateral_movement":  SecurityEventType.LATERAL_MOVEMENT,
    "c2_beaconing":      SecurityEventType.C2_BEACONING,
}


def _save_as_security_event(log: NormalizedLog) -> None:
    event_action = _EVENT_TYPE_MAP.get(log.event_action)
    if event_action is None:
        return
    event = SecurityEvent(
        event_id   = str(uuid.uuid4()),
        agent_id   = log.observer_hostname,
        hostname   = log.observer_hostname,
        event_action = event_action,
        severity   = log.severity,
        source_ip  = log.source_ip,
        message    = log.message,
        raw_data   = log.message,
        occurred_at = log.timestamp,
    )
    db.save_security_event(event)


# Global instance
detector_manager = DetectorManager()
