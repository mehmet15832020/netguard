"""
NetGuard Server — Alert endpoint'leri
"""

from fastapi import APIRouter, Depends, HTTPException
from server.auth import get_current_user, User, tenant_scope
from server.database import db

router = APIRouter()


@router.get("/alerts")
def list_alerts(
    status: str = None,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit 1-500 arasında olmalı")
    alerts = db.get_alerts(status=status, limit=limit, tenant_id=tenant_scope(current_user))
    return {
        "count": len(alerts),
        "alerts": [a.model_dump(mode="json") for a in alerts],
    }


@router.get("/alerts/summary")
def alert_summary(current_user: User = Depends(get_current_user)):
    tid = tenant_scope(current_user)
    active   = db.get_alerts(status="active",   limit=500, tenant_id=tid)
    resolved = db.get_alerts(status="resolved", limit=500, tenant_id=tid)
    return {
        "active":   len(active),
        "resolved": len(resolved),
        "total":    len(active) + len(resolved),
    }
