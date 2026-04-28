"""
NetGuard — Metrik sorgu endpoint'leri

GET /api/v1/metrics/agent/{agent_id}?range=1h   → InfluxDB geçmiş (CPU/RAM/net)
GET /api/v1/metrics/log-volume?range=24h         → SQLite saatlik log hacmi
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from server.auth import get_current_user, User, tenant_scope
from server.influx_writer import influx_writer
from server.storage import storage
import server.database as _db_mod

router = APIRouter()

VALID_RANGES = {"1h", "6h", "24h", "7d"}


@router.get("/metrics/agent/{agent_id}")
def agent_metrics(
    agent_id: str,
    range: str = Query("1h"),
    current_user: User = Depends(get_current_user),
):
    if range not in VALID_RANGES:
        raise HTTPException(400, "Geçersiz range. 1h/6h/24h/7d kullanın.")

    agent = storage.get_agent(agent_id)
    if not agent:
        raise HTTPException(404, "Agent bulunamadı.")
    tid = tenant_scope(current_user)
    if tid is not None and getattr(agent, "tenant_id", None) != tid:
        raise HTTPException(403, "Bu agent'a erişim yetkiniz yok.")

    data = influx_writer.query_agent_metrics(agent_id, range)
    if data is None:
        return {"available": False, "agent_id": agent_id, "range": range}

    return {"available": True, "agent_id": agent_id, "range": range, **data}


@router.get("/metrics/log-volume")
def log_volume(
    range: str = Query("24h"),
    current_user: User = Depends(get_current_user),
):
    if range not in VALID_RANGES:
        raise HTTPException(400, "Geçersiz range. 1h/6h/24h/7d kullanın.")

    db = _db_mod.db
    tid = tenant_scope(current_user)
    data = db.get_log_volume(range, tenant_id=tid)
    return {"range": range, "data": data}
