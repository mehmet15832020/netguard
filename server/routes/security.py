"""
NetGuard Server — Güvenlik olayı endpoint'leri

GET  /api/v1/security/events          → Güvenlik olaylarını listele
GET  /api/v1/security/events/summary  → Özet istatistik
POST /api/v1/security/scan            → Manuel auth.log taraması tetikle
"""

import logging
import os
import socket

from fastapi import APIRouter, HTTPException, Depends

from server.auth import get_current_user, User
from server.database import db
from server.security_log_parser import parse_auth_log, AUTH_LOG_PATH
from server.port_monitor import port_monitor
from server.config_monitor import config_monitor

logger = logging.getLogger(__name__)
router = APIRouter()

_AGENT_ID_FALLBACK = os.getenv("AGENT_ID", socket.gethostname())


@router.get("/security/events")
def list_security_events(
    event_type: str = None,
    source_ip: str = None,
    limit: int = 100,
    _: User = Depends(get_current_user),
):
    """Güvenlik olaylarını filtreli listele."""
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit 1-500 arasında olmalı")
    events = db.get_security_events(
        event_type=event_type,
        source_ip=source_ip,
        limit=limit,
    )
    return {"count": len(events), "events": events}


@router.get("/security/events/summary")
def security_summary(_: User = Depends(get_current_user)):
    """Olay tiplerine göre özet sayılar."""
    from shared.models import SecurityEventType
    summary = {}
    for et in SecurityEventType:
        events = db.get_security_events(event_type=et.value, limit=1000)
        summary[et.value] = len(events)
    return {"summary": summary}


@router.post("/security/scan")
def trigger_scan(agent_id: str = None, _: User = Depends(get_current_user)):
    """
    Auth log, port ve config taramasını manuel olarak tetikle.
    agent_id verilmezse sunucu kendi hostname'ini kullanır.
    """
    aid = agent_id or _AGENT_ID_FALLBACK

    log_events = parse_auth_log(agent_id=aid)
    port_events = port_monitor.check(agent_id=aid)
    config_events = config_monitor.check(agent_id=aid)

    total = len(log_events) + len(port_events) + len(config_events)
    logger.info(f"Manuel tarama: {total} olay tespit edildi")

    return {
        "scanned": True,
        "agent_id": aid,
        "events_found": {
            "auth_log": len(log_events),
            "port_changes": len(port_events),
            "config_changes": len(config_events),
            "total": total,
        },
    }
