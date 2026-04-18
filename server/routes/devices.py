"""
NetGuard Server — Unified Device endpoint'leri

GET  /api/v1/devices              → Tüm cihazları listele (agent + snmp + discovered)
GET  /api/v1/devices/{device_id}  → Tek cihaz detayı
"""

from fastapi import APIRouter, Depends, HTTPException
from server.auth import User, get_current_user
from server.database import db

router = APIRouter()


@router.get("/devices")
def list_devices(
    device_type: str = None,
    _: User = Depends(get_current_user),
):
    """
    Tüm cihazları listele.
    device_type filtresi: agent | snmp | discovered | hybrid
    """
    devices = db.get_devices(device_type=device_type)
    return {"count": len(devices), "devices": devices}


@router.get("/devices/{device_id}")
def get_device(
    device_id: str,
    _: User = Depends(get_current_user),
):
    """Tek bir cihazın detayını döndür."""
    device = db.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Cihaz bulunamadı: {device_id}")
    return device
