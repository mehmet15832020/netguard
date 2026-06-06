"""
NetGuard Server — Health endpoints

GET /api/v1/health         → Server ayakta mı?
GET /api/v1/health/sensors → Sensör sağlık metrikleri (CIS Control 13.1)
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Response
from server.auth import User, get_current_user
from server.limiter import _auth_key, limiter
from server.storage import storage

router = APIRouter()


@router.get("/health")
def health_check():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "registered_agents": storage.agent_count,
    }


@router.get("/health/sensors")
@limiter.limit("30/minute", key_func=_auth_key)
def sensor_health(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """Zeek/Suricata paket kaybı ve arayüz istatistikleri."""
    from server.sensor_health import get_all_sensor_health
    return get_all_sensor_health()