"""
NetGuard — V1-9 Aktif Yanıt Endpoint'leri

POST   /api/v1/response/block           → IP blokla (admin)
DELETE /api/v1/response/block/{ip}      → Blok kaldır (admin)
GET    /api/v1/response/blocks          → Aktif bloklar listesi (admin)
POST   /api/v1/response/playbook        → Incident için bloklama önerisi (admin)
"""

import asyncio
import ipaddress
import logging
import os
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from server.auth import User, get_current_user, tenant_scope
from server.database import db
from server.fp_manager import fp_manager

router = APIRouter()
logger = logging.getLogger(__name__)

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _load_protected_networks():
    nets = list(_RFC1918_NETWORKS)
    for cidr in os.getenv("PROTECTED_CIDRS", "").split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.warning("PROTECTED_CIDRS geçersiz CIDR atlandı: %s", cidr)
    return nets


_PROTECTED_NETWORKS = _load_protected_networks()


def _is_protected(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PROTECTED_NETWORKS)
    except ValueError:
        return False


def _require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role not in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Sadece admin kullanabilir")
    return current_user


class BlockRequest(BaseModel):
    ip: str
    reason: str
    source_incident_id: Optional[str] = None
    ttl_hours: Optional[float] = None
    force: bool = False

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Geçersiz IP adresi: {v}")
        return v

    @field_validator("reason")
    @classmethod
    def reason_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("reason boş bırakılamaz")
        return v.strip()

    @field_validator("ttl_hours")
    @classmethod
    def validate_ttl(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and v <= 0:
            raise ValueError("ttl_hours sıfırdan büyük olmalı")
        return v


class PlaybookRequest(BaseModel):
    incident_id: str


@router.post("/response/block", status_code=201)
async def block_ip(
    req: BlockRequest,
    current_user: User = Depends(_require_admin),
):
    if _is_protected(req.ip):
        raise HTTPException(
            status_code=400,
            detail=f"{req.ip} korumalı adres (RFC1918/loopback/PROTECTED_CIDRS) — bloklama reddedildi",
        )

    tid = current_user.tenant_id or "default"

    fp_rule_id = fp_manager.is_suppressed(
        event_action="",
        source_ip=req.ip,
        tenant_id=tid,
    )
    if fp_rule_id and not req.force:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{req.ip} aktif FP kuralıyla eşleşiyor (kural: {fp_rule_id}). "
                "Yine de bloklamak için force=true gönderin."
            ),
        )
    if fp_rule_id and req.force:
        db.save_audit_event(
            actor=current_user.username,
            action="ip_block_fp_override",
            resource=f"ip:{req.ip}",
            detail=f"fp_rule_id={fp_rule_id} force=true",
        )

    if req.source_incident_id:
        incident = db.get_incident(req.source_incident_id)
        if incident:
            min_sev = os.getenv("BLOCK_MIN_SEVERITY", "high")
            incident_sev = incident.get("severity", "info")
            if _SEVERITY_ORDER.get(incident_sev, 0) < _SEVERITY_ORDER.get(min_sev, 3):
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"Incident severity '{incident_sev}', minimum '{min_sev}' gerekiyor "
                        f"(BLOCK_MIN_SEVERITY env ile yapılandırılır). "
                        "Bağımsız bloklama için source_incident_id gönderme."
                    ),
                )

    if db.is_ip_blocked(req.ip, tenant_id=tid):
        raise HTTPException(status_code=409, detail=f"{req.ip} zaten bloklu")

    from server.active_response import active_response_manager
    result = await asyncio.to_thread(
        active_response_manager.block_ip,
        req.ip, req.reason, current_user.username,
        req.source_incident_id, tid, req.ttl_hours,
    )
    if not result["success"]:
        raise HTTPException(status_code=502, detail=f"Bloklama başarısız: {result['error']}")
    return result


@router.delete("/response/block/{ip}", status_code=200)
async def unblock_ip(
    ip: str,
    current_user: User = Depends(_require_admin),
):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Geçersiz IP: {ip}")

    tid = current_user.tenant_id or "default"
    from server.active_response import active_response_manager
    result = await asyncio.to_thread(
        active_response_manager.unblock_ip,
        ip, current_user.username, tid,
    )
    if not result["success"]:
        code = 404 if "bloklu değil" in result.get("error", "") else 502
        raise HTTPException(status_code=code, detail=result["error"])
    return result


@router.get("/response/blocks")
def list_blocks(current_user: User = Depends(_require_admin)):
    tid = tenant_scope(current_user)
    blocks = db.get_blocked_ips(active_only=True, tenant_id=tid)
    return {"count": len(blocks), "blocks": blocks}


@router.post("/response/playbook")
def suggest_playbook(
    req: PlaybookRequest,
    current_user: User = Depends(_require_admin),
):
    incident = db.get_incident(req.incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident bulunamadı")

    tid = current_user.tenant_id or "default"
    if incident.get("tenant_id", "default") != tid and current_user.role != "superadmin":
        raise HTTPException(status_code=404, detail="Incident bulunamadı")

    suggestions = []
    if incident.get("severity") == "critical":
        group_value = incident.get("group_value", "")
        if group_value and _IP_RE.match(group_value):
            suggestions.append({
                "action":          "block_ip",
                "ip":              group_value,
                "reason":          f"Critical incident: {incident['title']}",
                "incident_id":     req.incident_id,
                "already_blocked": db.is_ip_blocked(group_value, tenant_id=tid),
            })

    return {"incident_id": req.incident_id, "suggestions": suggestions}
