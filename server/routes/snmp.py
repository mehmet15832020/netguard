"""
NetGuard Server — SNMP endpoint'leri

POST /api/v1/snmp/poll            → Tek cihazı anlık sorgula
GET  /api/v1/snmp/devices         → Kayıtlı cihaz listesi
POST /api/v1/snmp/devices         → Cihaz ekle
DELETE /api/v1/snmp/devices/{host} → Cihaz sil
"""

from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from server.auth import get_current_user, require_admin, User
from server.database import db

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


class SNMPPollRequest(BaseModel):
    host: str
    community: str = "public"
    snmp_version: Literal["v2c", "v3"] = "v2c"
    v3_username: str = ""
    v3_auth_protocol: Literal["MD5", "SHA"] = "SHA"
    v3_auth_key: str = Field(default="", min_length=0)
    v3_priv_protocol: Literal["DES", "AES"] = "AES"
    v3_priv_key: str = ""


class SNMPDeviceRequest(BaseModel):
    host: str
    community: str = "public"
    label: str = ""
    snmp_version: Literal["v2c", "v3"] = "v2c"
    v3_username: str = ""
    v3_auth_protocol: Literal["MD5", "SHA"] = "SHA"
    v3_auth_key: str = ""
    v3_priv_protocol: Literal["DES", "AES"] = "AES"
    v3_priv_key: str = ""


def _strip_secrets(device: dict) -> dict:
    """API response'dan v3 key'lerini çıkar (write-only)."""
    return {k: v for k, v in device.items() if k not in ("snmp_v3_auth_key", "snmp_v3_priv_key")}


@router.post("/snmp/poll")
@limiter.limit("10/minute")
def snmp_poll(
    request: Request,
    body: SNMPPollRequest,
    _: User = Depends(get_current_user),
):
    """Belirtilen cihazı SNMP ile anlık sorgula."""
    from server.snmp_collector import poll_device
    return poll_device(
        host=body.host,
        community=body.community,
        snmp_version=body.snmp_version,
        v3_username=body.v3_username,
        v3_auth_protocol=body.v3_auth_protocol,
        v3_auth_key=body.v3_auth_key,
        v3_priv_protocol=body.v3_priv_protocol,
        v3_priv_key=body.v3_priv_key,
    )


@router.get("/snmp/devices")
def list_snmp_devices(_: User = Depends(get_current_user)):
    """Kayıtlı SNMP cihazlarını listele. v3 key'leri döndürülmez."""
    devices = db.get_snmp_devices(enabled_only=False)
    return {"count": len(devices), "devices": [_strip_secrets(d) for d in devices]}


@router.post("/snmp/devices", status_code=201)
def add_snmp_device(
    request: SNMPDeviceRequest,
    current_user: User = Depends(require_admin),
):
    """Yeni SNMP cihazı ekle (v2c veya v3). Admin gerekli."""
    added = db.add_snmp_device(
        host=request.host,
        community=request.community,
        label=request.label,
    )
    if not added:
        raise HTTPException(status_code=409, detail=f"{request.host} zaten kayıtlı")
    db.save_device(
        device_id=request.host,
        name=request.label if request.label else request.host,
        device_type="snmp",
        ip=request.host,
        snmp_community=request.community,
        snmp_version=request.snmp_version,
        snmp_v3_username=request.v3_username,
        snmp_v3_auth_protocol=request.v3_auth_protocol,
        snmp_v3_auth_key=request.v3_auth_key,
        snmp_v3_priv_protocol=request.v3_priv_protocol,
        snmp_v3_priv_key=request.v3_priv_key,
        status="unknown",
        tenant_id=current_user.tenant_id or "default",
    )
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
    db.remove_device(host)
    return {"removed": True, "host": host}
