"""
NetGuard — Threat Hunt Workbench Endpoints (F5)

GET    /api/v1/hunts                    → Kaydedilmiş hunt listesi
POST   /api/v1/hunts                    → Yeni hunt kaydet
GET    /api/v1/hunts/{hunt_id}          → Hunt detayı
PUT    /api/v1/hunts/{hunt_id}          → Hunt güncelle
DELETE /api/v1/hunts/{hunt_id}          → Hunt sil
PATCH  /api/v1/hunts/{hunt_id}/favorite → Favori toggle
POST   /api/v1/hunts/{hunt_id}/execute  → Kaydedilmiş hunt çalıştır
POST   /api/v1/hunts/execute            → Anlık (kayıtsız) hunt çalıştır
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from server.auth import User, get_current_user, tenant_scope
from server.database import db
from server.limiter import limiter, _auth_key
from server.log_store import log_store

logger = logging.getLogger(__name__)
router = APIRouter()

_VALID_HOURS   = frozenset({1, 6, 24, 48, 168, 720})
_VALID_SEV     = frozenset({"info", "warning", "critical"})
_VALID_CAT     = frozenset({"authentication", "network", "intrusion", "system", "endpoint", "file", ""})
_VALID_SRC     = frozenset({
    "suricata", "zeek", "syslog", "auth_log", "netguard", "windows",
    "pfsense", "opnsense", "cisco_asa", "fortigate", "vyos",
    "nginx", "apache", "netflow", "snmp", "",
})
_MAX_LIMIT     = 1000
_STATS_LIMIT   = 15   # top-N per group stat


# ── Pydantic modeller ─────────────────────────────────────────────────────────

class HuntFilters(BaseModel):
    source_ip:        Optional[str] = Field(default=None, max_length=64)
    destination_ip:   Optional[str] = Field(default=None, max_length=64)
    event_action:     Optional[str] = Field(default=None, max_length=120)
    event_category:   Optional[str] = Field(default=None, max_length=64)
    severity:         Optional[str] = Field(default=None, max_length=16)
    source_type:      Optional[str] = Field(default=None, max_length=32)
    network_protocol: Optional[str] = Field(default=None, max_length=16)
    keyword:          Optional[str] = Field(default=None, max_length=200)
    hours:            int            = Field(default=24, ge=1, le=720)
    limit:            int            = Field(default=200, ge=1, le=_MAX_LIMIT)

    def validate_enums(self) -> None:
        if self.severity and self.severity not in _VALID_SEV:
            raise HTTPException(status_code=422, detail=f"severity geçersiz: {self.severity}")
        if self.event_category and self.event_category not in _VALID_CAT:
            raise HTTPException(status_code=422, detail=f"event_category geçersiz: {self.event_category}")
        if self.source_type and self.source_type not in _VALID_SRC:
            raise HTTPException(status_code=422, detail=f"source_type geçersiz: {self.source_type}")


class HuntCreate(BaseModel):
    name:         str         = Field(min_length=1, max_length=120)
    description:  str         = Field(default="", max_length=500)
    filters:      HuntFilters
    tags:         list[str]   = Field(default=[], max_length=10)
    is_favorite:  bool        = False


class HuntUpdate(BaseModel):
    name:         str         = Field(min_length=1, max_length=120)
    description:  str         = Field(default="", max_length=500)
    filters:      HuntFilters
    tags:         list[str]   = Field(default=[], max_length=10)
    is_favorite:  bool        = False


# ── Yardımcılar ──────────────────────────────────────────────────────────────

def _execute_filters(filters: HuntFilters, tenant_id: str) -> dict:
    """Filtrelerle normalized_logs sorgula, istatistikleri hesapla."""
    since = datetime.now(timezone.utc) - timedelta(hours=filters.hours)

    logs = log_store.search(
        tenant_id=tenant_id,
        source_ip=filters.source_ip or None,
        destination_ip=filters.destination_ip or None,
        event_action=filters.event_action or None,
        event_category=filters.event_category or None,
        since=since,
        keyword=filters.keyword or None,
        limit=filters.limit,
        offset=0,
    )

    # severity filtresi log_store.search'te yok — client-side uygula
    if filters.severity:
        logs = [l for l in logs if l.get("severity") == filters.severity]

    # source_type filtresi — client-side
    if filters.source_type:
        logs = [l for l in logs if l.get("source_type") == filters.source_type]

    # network_protocol filtresi — client-side (case-insensitive)
    if filters.network_protocol:
        proto = filters.network_protocol.lower()
        logs = [l for l in logs if (l.get("network_protocol") or "").lower() == proto]

    # İstatistikler — gruba göre sayım
    stats: dict[str, list] = {}
    for group_col in ("source_ip", "event_action", "event_category", "severity"):
        freq: dict[str, int] = {}
        for log in logs:
            val = str(log.get(group_col) or "")
            if val:
                freq[val] = freq.get(val, 0) + 1
        stats[group_col] = sorted(
            [{"value": k, "count": v} for k, v in freq.items()],
            key=lambda x: -x["count"],
        )[:_STATS_LIMIT]

    return {"count": len(logs), "logs": logs, "stats": stats}


def _hunt_to_response(row: dict) -> dict:
    row = dict(row)
    row["filter_params"] = json.loads(row.get("filter_params") or "{}")
    row["tags"] = json.loads(row.get("tags") or "[]")
    return row


# ── CRUD endpoints ────────────────────────────────────────────────────────────

@router.get("/hunts")
@limiter.limit("60/minute", key_func=_auth_key)
def list_hunts(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user) or "default"
    rows = db.get_hunts(tenant_id=tid)
    return {"count": len(rows), "hunts": [_hunt_to_response(r) for r in rows]}


@router.post("/hunts", status_code=201)
@limiter.limit("20/minute", key_func=_auth_key)
def create_hunt(
    request: Request,
    response: Response,
    body: HuntCreate,
    current_user: User = Depends(get_current_user),
):
    body.filters.validate_enums()
    tid = tenant_scope(current_user) or "default"
    hunt_id = str(uuid.uuid4())
    db.create_hunt(
        hunt_id=hunt_id,
        tenant_id=tid,
        created_by=current_user.username,
        name=body.name,
        description=body.description,
        filter_params=body.filters.model_dump_json(),
        tags=json.dumps(body.tags),
    )
    if body.is_favorite:
        db.update_hunt(hunt_id, tid, body.name, body.description,
                       body.filters.model_dump_json(), json.dumps(body.tags), True)
    return {"hunt_id": hunt_id, "name": body.name}


@router.get("/hunts/{hunt_id}")
@limiter.limit("60/minute", key_func=_auth_key)
def get_hunt(
    request: Request,
    response: Response,
    hunt_id: str,
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user) or "default"
    row = db.get_hunt(hunt_id, tid)
    if row is None:
        raise HTTPException(status_code=404, detail="Hunt bulunamadı")
    return _hunt_to_response(row)


@router.put("/hunts/{hunt_id}")
@limiter.limit("20/minute", key_func=_auth_key)
def update_hunt(
    request: Request,
    response: Response,
    hunt_id: str,
    body: HuntUpdate,
    current_user: User = Depends(get_current_user),
):
    body.filters.validate_enums()
    tid = tenant_scope(current_user) or "default"
    ok = db.update_hunt(
        hunt_id=hunt_id,
        tenant_id=tid,
        name=body.name,
        description=body.description,
        filter_params=body.filters.model_dump_json(),
        tags=json.dumps(body.tags),
        is_favorite=body.is_favorite,
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Hunt bulunamadı")
    return {"hunt_id": hunt_id, "updated": True}


@router.delete("/hunts/{hunt_id}", status_code=204)
@limiter.limit("20/minute", key_func=_auth_key)
def delete_hunt(
    request: Request,
    response: Response,
    hunt_id: str,
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user) or "default"
    if not db.delete_hunt(hunt_id, tid):
        raise HTTPException(status_code=404, detail="Hunt bulunamadı")


@router.patch("/hunts/{hunt_id}/favorite")
@limiter.limit("30/minute", key_func=_auth_key)
def toggle_favorite(
    request: Request,
    response: Response,
    hunt_id: str,
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user) or "default"
    row = db.get_hunt(hunt_id, tid)
    if row is None:
        raise HTTPException(status_code=404, detail="Hunt bulunamadı")
    new_fav = not row["is_favorite"]
    db.update_hunt(
        hunt_id, tid,
        row["name"], row["description"],
        row["filter_params"], row["tags"],
        new_fav,
    )
    return {"hunt_id": hunt_id, "is_favorite": new_fav}


# ── Execute endpoints ─────────────────────────────────────────────────────────

@router.post("/hunts/{hunt_id}/execute")
@limiter.limit("15/minute", key_func=_auth_key)
def execute_hunt(
    request: Request,
    response: Response,
    hunt_id: str,
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user) or "default"
    row = db.get_hunt(hunt_id, tid)
    if row is None:
        raise HTTPException(status_code=404, detail="Hunt bulunamadı")

    try:
        params = json.loads(row["filter_params"] or "{}")
        filters = HuntFilters(**params)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Hunt filtresi geçersiz: {exc}")

    result = _execute_filters(filters, tid)
    db.record_hunt_run(hunt_id, tid, result["count"])
    return result


@router.post("/hunts/execute")
@limiter.limit("15/minute", key_func=_auth_key)
def execute_adhoc(
    request: Request,
    response: Response,
    body: HuntFilters,
    current_user: User = Depends(get_current_user),
):
    body.validate_enums()
    tid = tenant_scope(current_user) or "default"
    return _execute_filters(body, tid)
