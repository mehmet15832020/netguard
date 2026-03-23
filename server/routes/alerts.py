"""
NetGuard Server — Alert endpoint'leri
"""

from fastapi import APIRouter, HTTPException
from server.storage import storage

router = APIRouter()


@router.get("/alerts")
def list_alerts(status: str = None, limit: int = 100):
    """Alert listesini döndür."""
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit 1-500 arasında olmalı")
    alerts = storage.get_alerts(status=status, limit=limit)
    return {
        "count": len(alerts),
        "alerts": alerts
    }


@router.get("/alerts/summary")
def alert_summary():
    """Özet: kaç aktif, kaç resolved alert var."""
    active = storage.get_alerts(status="active")
    resolved = storage.get_alerts(status="resolved")
    return {
        "active": len(active),
        "resolved": len(resolved),
        "total": len(active) + len(resolved),
    }