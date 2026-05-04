"""
NetGuard — Incident Zenginleştirme

GET /incidents/{id} yanıtına ilgili normalize loglar, MITRE ATT&CK
teknikleri ve threat intel verisi ekler. Hesaplama sorgu anında yapılır,
DB'de saklanmaz — hafif ve her zaman güncel.
"""

import logging
from typing import Optional

from server.database import db
from server import threat_intel

logger = logging.getLogger(__name__)

_WINDOW_MINUTES = 30
_MAX_RELATED_LOGS = 20


def enrich_incident(incident: dict) -> dict:
    """
    Incident dict'ine `enrichment` anahtarı ekler.
    Giriş dict değiştirilmez; genişletilmiş kopya döner.
    """
    enrichment: dict = {
        "mitre_techniques": [],
        "mitre_tactics":    [],
        "related_logs":     [],
        "threat_intel":     None,
    }

    source_event_id: Optional[str] = incident.get("source_event_id")
    group_value:     Optional[str] = incident.get("group_value")
    created_at:      Optional[str] = incident.get("created_at")

    _fill_mitre(enrichment, source_event_id)
    _fill_related_logs(enrichment, group_value, created_at)
    _fill_threat_intel(enrichment, group_value)

    return {**incident, "enrichment": enrichment}


def _fill_mitre(enrichment: dict, source_event_id: Optional[str]) -> None:
    if not source_event_id:
        return
    try:
        ce = db.get_correlated_event_by_id(source_event_id)
        if ce:
            enrichment["mitre_techniques"] = ce.mitre_techniques
            enrichment["mitre_tactics"]    = ce.mitre_tactics
    except Exception as exc:
        logger.debug("MITRE enrichment başarısız: %s", exc)


def _fill_related_logs(
    enrichment: dict,
    src_ip: Optional[str],
    around_iso: Optional[str],
) -> None:
    if not src_ip or not around_iso:
        return
    try:
        logs = db.get_related_logs_for_incident(
            src_ip=src_ip,
            around_iso=around_iso,
            window_minutes=_WINDOW_MINUTES,
            limit=_MAX_RELATED_LOGS,
        )
        enrichment["related_logs"] = [
            {
                "log_id":      log.log_id,
                "timestamp":   log.timestamp.isoformat(),
                "event_type":  log.event_type,
                "severity":    log.severity,
                "source_type": log.source_type.value,
                "src_ip":      log.src_ip,
                "dst_ip":      log.dst_ip,
                "message":     log.message[:200],
            }
            for log in logs
        ]
    except Exception as exc:
        logger.debug("Related logs enrichment başarısız: %s", exc)


def _fill_threat_intel(enrichment: dict, ip: Optional[str]) -> None:
    if not ip:
        return
    try:
        ti = threat_intel.lookup(ip)
        if ti:
            enrichment["threat_intel"] = {
                "score":        ti.get("score", 0),
                "total_reports": ti.get("total_reports", 0),
                "country_code": ti.get("country_code", ""),
                "isp":          ti.get("isp", ""),
            }
    except Exception as exc:
        logger.debug("Threat intel enrichment başarısız: %s", exc)
