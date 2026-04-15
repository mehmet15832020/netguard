"""
NetGuard Server — SNMP endpoint'leri

POST /api/v1/snmp/poll            → Tek cihazı anlık sorgula
GET  /api/v1/snmp/devices         → Kayıtlı cihaz listesi
POST /api/v1/snmp/devices         → Cihaz ekle
DELETE /api/v1/snmp/devices/{host} → Cihaz sil
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from server.auth import get_current_user, User
from server.database import db

router = APIRouter()


class SNMPPollRequest(BaseModel):
    host: str
    community: str = "public"


class SNMPDeviceRequest(BaseModel):
    host: str
    community: str = "public"
    label: str = ""


@router.post("/snmp/poll")
def snmp_poll(
    request: SNMPPollRequest,
    _: User = Depends(get_current_user),
):
    """Belirtilen cihazı SNMP ile anlık sorgula."""
    from server.snmp_collector import poll_device
    return poll_device(request.host, request.community)


@router.get("/snmp/devices")
def list_snmp_devices(_: User = Depends(get_current_user)):
    """Kayıtlı SNMP cihazlarını listele."""
    devices = db.get_snmp_devices(enabled_only=False)
    return {"count": len(devices), "devices": devices}


@router.post("/snmp/devices", status_code=201)
def add_snmp_device(
    request: SNMPDeviceRequest,
    _: User = Depends(get_current_user),
):
    """Yeni SNMP cihazı ekle."""
    added = db.add_snmp_device(
        host=request.host,
        community=request.community,
        label=request.label,
    )
    if not added:
        raise HTTPException(status_code=409, detail=f"{request.host} zaten kayıtlı")
    return {"added": True, "host": request.host}


@router.delete("/snmp/devices/{host}")
def remove_snmp_device(
    host: str,
    _: User = Depends(get_current_user),
):
    """SNMP cihazını sil."""
    removed = db.remove_snmp_device(host)
    if not removed:
        raise HTTPException(status_code=404, detail=f"{host} bulunamadı")
    return {"removed": True, "host": host}
