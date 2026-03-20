"""
NetGuard Server — Agent endpoint'leri

POST /api/v1/agents/register     → Agent kaydı
POST /api/v1/agents/metrics      → Metrik al
GET  /api/v1/agents              → Tüm agent'lar
GET  /api/v1/agents/{id}/latest  → Son snapshot
GET  /api/v1/agents/{id}/history → Geçmiş snapshot'lar
"""

import logging
from fastapi import APIRouter, HTTPException
from shared.models import AgentRegistration, MetricSnapshot
from server.storage import storage

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/agents/register", status_code=201)
def register_agent(registration: AgentRegistration):
    """Agent'ı kaydet."""
    storage.register_agent(registration)
    logger.info(f"Agent kaydedildi: {registration.hostname} ({registration.agent_id})")
    return {"status": "registered", "agent_id": registration.agent_id}


@router.post("/agents/metrics", status_code=202)
def receive_metrics(snapshot: MetricSnapshot):
    """Agent'tan gelen snapshot'ı depola."""
    storage.store_snapshot(snapshot)
    logger.debug(
        f"Snapshot alındı: {snapshot.hostname} | "
        f"CPU: {snapshot.cpu.usage_percent:.1f}% | "
        f"RAM: {snapshot.memory.usage_percent:.1f}%"
    )
    return {"status": "accepted"}


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