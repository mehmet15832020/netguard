"""
NetGuard Server — Alert endpoint'leri
"""

from fastapi import APIRouter, Depends, HTTPException
from server.auth import get_current_user, User
from server.storage import storage

router = APIRouter()


@router.get("/alerts")
def list_alerts(
    status: str = None,
    limit: int = 100,
    _: User = Depends(get_current_user),
):
    """Alert listesini döndür."""
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit 1-500 arasında olmalı")
    alerts = storage.get_alerts(status=status, limit=limit)
    return {
        "count": len(alerts),
        "alerts": alerts
    }


@router.get("/alerts/summary")
def alert_summary(_: User = Depends(get_current_user)):
    """Özet: kaç aktif, kaç resolved alert var."""
    active = storage.get_alerts(status="active")
    resolved = storage.get_alerts(status="resolved")
    return {
        "active": len(active),
        "resolved": len(resolved),
        "total": len(active) + len(resolved),
    }