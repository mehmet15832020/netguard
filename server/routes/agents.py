"""
NetGuard Server — Agent endpoint'leri

POST /api/v1/agents/register     → Agent kaydı
POST /api/v1/agents/metrics      → Metrik al
GET  /api/v1/agents              → Tüm agent'lar
GET  /api/v1/agents/{id}/latest  → Son snapshot
GET  /api/v1/agents/{id}/history → Geçmiş snapshot'lar
"""

import logging
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from shared.models import (
    AgentRegistration, MetricSnapshot, SecurityEvent, SecurityEventType,
    NormalizedLog, LogSourceType, LogCategory, TrafficSummary,
)
from server.storage import storage
from server.database import db
from server.alert_engine import alert_engine
from server.influx_writer import influx_writer
from server.notifier import notifier
from server.ws_manager import ws_manager
from server.auth import get_agent_from_api_key
from server.attack_chain import attack_chain_tracker, chain_trigger_to_correlated_event

SUSPICIOUS_WARN_THRESHOLD    = 5
SUSPICIOUS_CRITICAL_THRESHOLD = 15


logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/agents/register", status_code=201)
def register_agent(registration: AgentRegistration):
    """Agent'ı kaydet."""
    storage.register_agent(registration)
    db.save_device(
        device_id=registration.agent_id,
        name=registration.hostname,
        device_type="agent",
        os_info=f"{registration.os_name} {registration.os_version}",
        status="up",
    )
    logger.info(f"Agent kaydedildi: {registration.hostname} ({registration.agent_id})")
    return {"status": "registered", "agent_id": registration.agent_id}




def _process_traffic_summary(agent_id: str, hostname: str, summary: TrafficSummary) -> None:
    """
    Gelen TrafficSummary'yi işler:
    - InfluxDB'ye protokol/paket metrikleri yazar
    - Şüpheli paket eşiği aşıldıysa normalized_log kaydeder
    - Aktif kaynak IP'leri kill chain tracker'a besler
    """
    influx_writer.write_traffic(agent_id, hostname, summary)

    if summary.suspicious_packet_count >= SUSPICIOUS_WARN_THRESHOLD:
        severity = "critical" if summary.suspicious_packet_count >= SUSPICIOUS_CRITICAL_THRESHOLD else "warning"
        now = datetime.now(timezone.utc)
        log = NormalizedLog(
            log_id      = str(uuid.uuid4()),
            raw_id      = str(uuid.uuid4()),
            source_type = LogSourceType.NETGUARD,
            source_host = hostname,
            timestamp   = summary.captured_at,
            received_at = now,
            severity    = severity,
            category    = LogCategory.NETWORK,
            event_type  = "suspicious_traffic",
            src_ip      = summary.top_src_ips[0] if summary.top_src_ips else None,
            message     = (
                f"{hostname}: {summary.suspicious_packet_count} şüpheli paket "
                f"({summary.interface}, {summary.duration_sec:.0f}s)"
            ),
            processed_at = now,
        )
        db.save_normalized_log(log)
        logger.warning(
            f"Şüpheli trafik: {hostname} — {summary.suspicious_packet_count} paket "
            f"({summary.interface})"
        )

        try:
            for src_ip in summary.top_src_ips[:3]:
                trigger = attack_chain_tracker.record(
                    src_ip=src_ip,
                    event_type="port_scan",
                    occurred_at=summary.captured_at,
                )
                if trigger:
                    chain_trigger_to_correlated_event(trigger, db_save=True)
                    logger.warning(f"Kill chain (traffic): {src_ip} — {trigger['chain_type']}")
        except Exception as exc:
            logger.debug(f"Kill chain feed hatası: {exc}")


@router.post("/agents/metrics", status_code=202)
async def receive_metrics(snapshot: MetricSnapshot):
    """Agent'tan gelen snapshot'ı depola, alert kontrolü yap ve WS'e broadcast et."""
    storage.store_snapshot(snapshot)

    # InfluxDB'ye yaz
    influx_writer.write_snapshot(snapshot)

    # Trafik özeti varsa işle
    if snapshot.traffic_summary:
        try:
            _process_traffic_summary(snapshot.agent_id, snapshot.hostname, snapshot.traffic_summary)
        except Exception as exc:
            logger.error(f"Traffic summary işleme hatası: {exc}")

    # Alert Engine'i çalıştır
    alerts = alert_engine.evaluate(snapshot)
    for alert in alerts:
        db.save_alert(alert)
        notifier.notify(alert)
        await ws_manager.broadcast("alert", alert.model_dump(mode="json"))

    # Metriği dashboard'a gerçek zamanlı gönder
    await ws_manager.broadcast("metric", snapshot.model_dump(mode="json"))

    return {"status": "accepted", "alerts_triggered": len(alerts)}

class SecurityEventItem(BaseModel):
    event_type: str
    severity: str = "warning"
    source_ip: str | None = None
    username: str | None = None
    message: str
    raw_data: str | None = None
    occurred_at: str | None = None


class SecurityEventBatch(BaseModel):
    hostname: str
    events: list[SecurityEventItem]


@router.post("/agents/security-events", status_code=202)
def receive_security_events(
    batch: SecurityEventBatch,
    agent_id: str = Depends(get_agent_from_api_key),
):
    """Agent'tan gelen güvenlik olaylarını API key doğrulamasıyla kaydet."""
    saved = 0
    for ev in batch.events:
        try:
            event = SecurityEvent(
                event_id    = str(uuid.uuid4()),
                agent_id    = agent_id,
                hostname    = batch.hostname,
                event_type  = SecurityEventType(ev.event_type),
                severity    = ev.severity,
                source_ip   = ev.source_ip,
                username    = ev.username,
                message     = ev.message,
                raw_data    = ev.raw_data,
                occurred_at = datetime.fromisoformat(ev.occurred_at) if ev.occurred_at else datetime.now(timezone.utc),
            )
            db.save_security_event(event)
            saved += 1
            if ev.source_ip:
                try:
                    from server.attack_chain import attack_chain_tracker, chain_trigger_to_correlated_event
                    trigger = attack_chain_tracker.record(
                        src_ip=ev.source_ip,
                        event_type=ev.event_type,
                        occurred_at=event.occurred_at,
                    )
                    if trigger:
                        chain_event = chain_trigger_to_correlated_event(trigger, db_save=True)
                        logger.warning(f"SALDIRI ZİNCİRİ (agent): {ev.source_ip} — {trigger['chain_type']}")
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Güvenlik olayı kaydedilemedi: {e}")
    return {"status": "accepted", "saved": saved}


@router.get("/agents")
def list_agents():
    """Kayıtlı tüm agent'ları listele."""
    agents = storage.get_all_agents()
    return {
        "count": len(agents),
        "agents": [
            {
                "agent_id": r.registration.agent_id,
                "hostname": r.registration.hostname,
                "os": f"{r.registration.os_name} {r.registration.os_version}",
                "last_seen": r.last_seen.isoformat(),
                "snapshot_count": len(r.snapshots),
            }
            for r in agents
        ],
    }


@router.get("/agents/{agent_id}/latest")
def get_latest_snapshot(agent_id: str):
    """Agent'ın en son metriklerini döndür."""
    snapshot = storage.get_latest_snapshot(agent_id)
    if snapshot is None:
        raise HTTPException(
            status_code=404,
            detail=f"Agent bulunamadı veya henüz metrik gönderilmedi: {agent_id}"
        )
    return snapshot


@router.get("/agents/{agent_id}/history")
def get_snapshot_history(agent_id: str, limit: int = 60):
    """Agent'ın son N snapshot'ını döndür."""
    if limit < 1 or limit > 360:
        raise HTTPException(status_code=400, detail="limit 1-360 arasında olmalı")

    snapshots = storage.get_snapshots(agent_id, limit=limit)
    if not snapshots:
        raise HTTPException(status_code=404, detail=f"Agent bulunamadı: {agent_id}")

    return {
        "agent_id": agent_id,
        "count": len(snapshots),
        "snapshots": snapshots,
    }

@router.get("/agents/{agent_id}/traffic")
def get_traffic_summary(agent_id: str):
    """Agent'ın en son trafik özetini döndür."""
    snapshot = storage.get_latest_snapshot(agent_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail=f"Agent bulunamadı: {agent_id}")
    if snapshot.traffic_summary is None:
        raise HTTPException(
            status_code=404,
            detail="Henüz trafik verisi yok — agent başlatıldıktan 30 saniye sonra tekrar dene"
        )
    return snapshot.traffic_summary

@router.get("/agents/{agent_id}/processes")
def get_processes(agent_id: str):
    """Agent'ın en son process listesini döndür."""
    snapshot = storage.get_latest_snapshot(agent_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail=f"Agent bulunamadı: {agent_id}")
    if snapshot.process_snapshot is None:
        raise HTTPException(status_code=404, detail="Henüz process verisi yok")
    return snapshot.process_snapshot