"""
NetGuard — False Positive Rules API

GET    /fp-rules          — tüm kuralları listele (aktif + pasif)
POST   /fp-rules          — yeni kural oluştur
DELETE /fp-rules/{id}     — kuralı devre dışı bırak (soft delete)
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from server.auth import get_current_user
from server.database import db
from server.fp_manager import fp_manager

router = APIRouter(prefix="/fp-rules", tags=["fp-rules"])

_DEFAULT_EXPIRY_DAYS = 30


class FPRuleCreate(BaseModel):
    event_action:     Optional[str] = None
    source_ip:        Optional[str] = None
    destination_ip:   Optional[str] = None
    destination_port: Optional[str] = None
    observer_hostname: Optional[str] = None
    tenant_id:        str = "default"
    reason:           str
    expires_in_days:  Optional[int] = _DEFAULT_EXPIRY_DAYS

    @field_validator("reason")
    @classmethod
    def reason_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("reason boş bırakılamaz")
        return v.strip()

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        import ipaddress
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f"Geçersiz IP veya CIDR: {v}")
        return v


@router.get("")
def list_fp_rules(
    tenant_id: str = "default",
    active_only: bool = False,
    _user=Depends(get_current_user),
):
    rules = db.get_active_fp_rules(tenant_id) if active_only else db.get_all_fp_rules(tenant_id)
    return rules


@router.post("", status_code=201)
def create_fp_rule(
    body: FPRuleCreate,
    _user=Depends(get_current_user),
):
    now = datetime.now(timezone.utc)
    expires_at = None
    if body.expires_in_days is not None:
        expires_at = (now + timedelta(days=body.expires_in_days)).isoformat()

    fp_rule_id = str(uuid.uuid4())
    created_by = _user.get("username", "admin") if isinstance(_user, dict) else str(_user)

    db.create_fp_rule(
        fp_rule_id=fp_rule_id,
        event_action=body.event_action or None,
        source_ip=body.source_ip or None,
        destination_ip=body.destination_ip or None,
        destination_port=body.destination_port or None,
        observer_hostname=body.observer_hostname or None,
        tenant_id=body.tenant_id,
        reason=body.reason,
        created_by=created_by,
        created_at=now.isoformat(),
        expires_at=expires_at,
    )
    fp_manager.invalidate()

    return {
        "fp_rule_id": fp_rule_id,
        "created_at": now.isoformat(),
        "expires_at": expires_at,
    }


@router.delete("/{fp_rule_id}", status_code=200)
def deactivate_fp_rule(
    fp_rule_id: str,
    tenant_id: str = "default",
    _user=Depends(get_current_user),
):
    ok = db.deactivate_fp_rule(fp_rule_id=fp_rule_id, tenant_id=tenant_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {fp_rule_id}")
    fp_manager.invalidate()
    return {"deactivated": fp_rule_id}
