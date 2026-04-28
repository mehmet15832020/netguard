"""
NetGuard Server — Unified Device endpoint'leri

GET  /api/v1/devices              → Tüm cihazları listele (agent + snmp + discovered)
GET  /api/v1/devices/{device_id}  → Tek cihaz detayı
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Literal, Optional
from server.auth import User, get_current_user, require_admin, tenant_scope
from server.database import db

router = APIRouter()


@router.get("/devices")
def list_devices(
    device_type: str = None,
    current_user: User = Depends(get_current_user),
):
    """
    Tüm cihazları listele.
    device_type filtresi: agent | snmp | discovered | hybrid
    """
    devices = db.get_devices(device_type=device_type, tenant_id=tenant_scope(current_user))
    return {"count": len(devices), "devices": devices}


class SNMPSettingsRequest(BaseModel):
    community: str = "public"
    snmp_version: Literal["v2c", "v3"] = "v2c"
    v3_username: Optional[str] = ""
    v3_auth_protocol: Literal["MD5", "SHA"] = "SHA"
    v3_auth_key: Optional[str] = ""
    v3_priv_protocol: Literal["DES", "AES"] = "AES"
    v3_priv_key: Optional[str] = ""


@router.patch("/devices/{device_id}/snmp")
def update_snmp_settings(
    device_id: str,
    body: SNMPSettingsRequest,
    _: User = Depends(require_admin),
):
    """Cihazın SNMP ayarlarını güncelle."""
    updated = db.update_device_snmp(
        device_id=device_id,
        community=body.community,
        version=body.snmp_version,
        v3_username=body.v3_username or "",
        v3_auth_protocol=body.v3_auth_protocol,
        v3_auth_key=body.v3_auth_key or "",
        v3_priv_protocol=body.v3_priv_protocol,
        v3_priv_key=body.v3_priv_key or "",
    )
    if not updated:
        raise HTTPException(status_code=404, detail=f"Cihaz bulunamadı: {device_id}")
    return {"ok": True, "device_id": device_id}


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


@router.get("/devices/{device_id}/alerts")
def device_alerts(
    device_id: str,
    limit: int = 20,
    current_user: User = Depends(get_current_user),
):
    """Cihaza ait alert geçmişini döndür (agent_id == device_id)."""
    device = db.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Cihaz bulunamadı: {device_id}")
    tid = tenant_scope(current_user)
    alerts = db.get_alerts(agent_id=device_id, limit=limit, tenant_id=tid)
    return {"count": len(alerts), "alerts": [a.model_dump(mode="json") for a in alerts]}
