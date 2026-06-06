"""
NetGuard Server — Korelasyon endpoint'leri

GET    /api/v1/correlation/events              → Korelasyon olaylarını listele
GET    /api/v1/correlation/rules               → Tüm kuralları listele (disabled dahil)
GET    /api/v1/correlation/rules/{rule_id}     → Tek kural detayı
POST   /api/v1/correlation/rules               → Yeni kural oluştur
PUT    /api/v1/correlation/rules               → Kuralları bulk güncelle (compat)
PUT    /api/v1/correlation/rules/{rule_id}     → Tek kuralı güncelle
DELETE /api/v1/correlation/rules/{rule_id}     → Kuralı sil
PATCH  /api/v1/correlation/rules/{rule_id}/toggle → Enable/disable toggle
POST   /api/v1/correlation/run                 → Korelasyonu manuel tetikle
POST   /api/v1/correlation/rules/reload        → Kural dosyasını yeniden yükle
"""

import json
import logging
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from server.auth import User, get_current_user, require_admin, tenant_scope
from server.correlator import correlator, _VALID_GROUP_COLS
from server.database import db
from server.limiter import limiter, _auth_key
from server.alert_explainer import explain_event

logger = logging.getLogger(__name__)
router = APIRouter()

_rules_lock = threading.Lock()

_VALID_SEVERITIES = frozenset({"info", "warning", "high", "critical"})
_RULE_ID_RE = re.compile(r"^[a-z0-9_]{2,64}$")


# ─── Yardımcılar ─────────────────────────────────────────────────────────────

def _read_all_rules() -> list[dict]:
    """JSON dosyasından tüm kuralları oku (disabled dahil). Lock dışında çağrılabilir."""
    try:
        return json.loads(Path(correlator._rules_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"Kural dosyası okunamadı: {exc}")


def _write_rules_atomic(rules: list[dict]) -> int:
    """Kuralları atomik yaz (tempfile+os.replace), correlator'ı hot-reload et.
    Çağıran taraf _rules_lock'u tutmalıdır."""
    target = Path(correlator._rules_path)
    data = json.dumps(rules, ensure_ascii=False, indent=2)
    fd, tmp = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(target))
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=f"Dosya yazılamadı: {exc}")
    return correlator.load_rules()


# ─── Pydantic modeller ────────────────────────────────────────────────────────

class CorrelationRuleIn(BaseModel):
    rule_id:             str
    name:                str                   = Field(min_length=2, max_length=120)
    description:         str                   = Field(default="", max_length=500)
    match_event_action:  str                   = Field(default="", max_length=120)
    group_by:            str                   = "source_ip"
    distinct_by:         Optional[str]         = None
    window_seconds:      int                   = Field(ge=10, le=86400)
    threshold:           int                   = Field(ge=1, le=10000)
    severity:            str
    output_event_action: str                   = Field(min_length=2, max_length=120)
    enabled:             bool                  = True
    match_severity:      Optional[str]         = None
    keywords:            Optional[list[str]]   = Field(default=None, max_length=50)
    tags:                list[str]             = Field(default=[], max_length=50)

    @field_validator("rule_id")
    @classmethod
    def rule_id_slug(cls, v: str) -> str:
        if not _RULE_ID_RE.match(v):
            raise ValueError("rule_id sadece küçük harf, rakam ve _ içermeli (2-64 karakter)")
        return v

    @field_validator("severity", "match_severity", mode="before")
    @classmethod
    def valid_severity(cls, v: Any) -> Any:
        if v is not None and v not in _VALID_SEVERITIES:
            raise ValueError(f"severity {_VALID_SEVERITIES} içinden biri olmalı")
        return v

    @field_validator("group_by")
    @classmethod
    def valid_group_by(cls, v: str) -> str:
        if v not in _VALID_GROUP_COLS:
            raise ValueError(f"group_by geçersiz: {v}. Geçerli: {sorted(_VALID_GROUP_COLS)}")
        return v

    @field_validator("distinct_by", mode="before")
    @classmethod
    def valid_distinct_by(cls, v: Any) -> Any:
        if v is not None and v not in _VALID_GROUP_COLS:
            raise ValueError(f"distinct_by geçersiz: {v}")
        return v


class RulesUpdateRequest(BaseModel):
    rules: list[dict[str, Any]]


# ─── Events ──────────────────────────────────────────────────────────────────

@router.get("/correlation/events/{corr_id}")
@limiter.limit("60/minute", key_func=_auth_key)
def get_correlated_event(
    request: Request,
    response: Response,
    corr_id: str,
    current_user: User = Depends(get_current_user),
):
    scope = tenant_scope(current_user)
    event = db.get_correlated_event_by_id(corr_id, tenant_id=scope)
    if event is None:
        raise HTTPException(status_code=404, detail="Olay bulunamadı")
    return event


@router.post("/correlation/events/{corr_id}/explain")
@limiter.limit("5/minute", key_func=_auth_key)
def explain_correlated_event(
    request: Request,
    response: Response,
    corr_id: str,
    current_user: User = Depends(get_current_user),
):
    scope = tenant_scope(current_user)
    tid   = scope or "default"

    event = db.get_correlated_event_by_id(corr_id, tenant_id=scope)
    if event is None:
        raise HTTPException(status_code=404, detail="Olay bulunamadı")

    recent_logs = db.get_normalized_logs(
        event_action=event.event_action,
        source_ip=event.group_value if _is_ip(event.group_value) else None,
        since=event.first_seen,
        limit=5,
        tenant_id=tid,
    )
    log_dicts = [lg.model_dump(mode="json") for lg in recent_logs]

    try:
        result = explain_event(
            event_data=event.model_dump(mode="json"),
            recent_logs=log_dicts,
            db=db,
            tenant_id=tid,
            corr_id=corr_id,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    return result


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


@router.get("/correlation/events/{corr_id}/context")
@limiter.limit("30/minute", key_func=_auth_key)
def get_event_context(
    request: Request,
    response: Response,
    corr_id: str,
    window_minutes: int = 5,
    current_user: User = Depends(get_current_user),
):
    """Alert bağlam pivot: aynı IP + zaman diliminden Zeek/Suricata/NetFlow kayıtları."""
    from datetime import timedelta
    if window_minutes < 1 or window_minutes > 60:
        raise HTTPException(status_code=400, detail="window_minutes 1-60 arasında olmalı")

    scope = tenant_scope(current_user)
    tid = scope or "default"

    event = db.get_correlated_event_by_id(corr_id, tenant_id=scope)
    if event is None:
        raise HTTPException(status_code=404, detail="Olay bulunamadı")

    if not _is_ip(event.group_value):
        return {
            "corr_id": corr_id,
            "pivot_ip": None,
            "window_minutes": window_minutes,
            "logs_by_source": {},
            "community_ids": [],
            "truncated": False,
            "message": "IP tabanlı korelasyon değil — bağlam pivot desteklenmiyor",
        }

    delta = timedelta(minutes=window_minutes)
    since = event.first_seen - delta
    until = event.last_seen + delta

    result = db.get_event_context_logs(
        ip=event.group_value,
        since=since,
        until=until,
        tenant_id=tid,
    )
    logs = result["logs"]

    logs_by_source: dict[str, list] = {}
    community_ids: set[str] = set()
    for log in logs:
        src = (log.get("source_type") or "unknown").lower()
        logs_by_source.setdefault(src, []).append(log)
        cid = log.get("community_id")
        if cid:
            community_ids.add(cid)

    return {
        "corr_id": corr_id,
        "pivot_ip": event.group_value,
        "window_minutes": window_minutes,
        "first_seen": event.first_seen,
        "last_seen": event.last_seen,
        "logs_by_source": logs_by_source,
        "community_ids": sorted(community_ids),
        "total_logs": len(logs),
        "truncated": result["truncated"],
    }


@router.get("/correlation/events")
def list_correlated_events(
    rule_id: str = None,
    severity: str = None,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit 1-500 arasında olmalı")
    events = db.get_correlated_events(
        rule_id=rule_id, severity=severity, limit=limit,
        tenant_id=tenant_scope(current_user),
    )
    return {"count": len(events), "events": events}


# ─── Rules CRUD ──────────────────────────────────────────────────────────────

@router.get("/correlation/rules")
def list_rules(_: User = Depends(get_current_user)):
    rules = _read_all_rules()
    return {"count": len(rules), "rules": rules}


@router.get("/correlation/rules/{rule_id}")
def get_rule(rule_id: str, _: User = Depends(get_current_user)):
    rules = _read_all_rules()
    rule = next((r for r in rules if r.get("rule_id") == rule_id), None)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")
    return rule


@router.post("/correlation/rules", status_code=201)
@limiter.limit("20/minute", key_func=_auth_key)
def create_rule(request: Request, response: Response, body: CorrelationRuleIn, _: User = Depends(require_admin)):
    with _rules_lock:
        rules = _read_all_rules()
        if any(r.get("rule_id") == body.rule_id for r in rules):
            raise HTTPException(status_code=409, detail=f"rule_id zaten mevcut: {body.rule_id}")
        rules.append(body.model_dump())
        loaded = _write_rules_atomic(rules)
    logger.info(f"Korelasyon kuralı oluşturuldu: {body.rule_id}")
    return {"rule_id": body.rule_id, "loaded_count": loaded}


@router.put("/correlation/rules/{rule_id}")
@limiter.limit("20/minute", key_func=_auth_key)
def update_rule(request: Request, response: Response, rule_id: str, body: CorrelationRuleIn, _: User = Depends(require_admin)):
    with _rules_lock:
        rules = _read_all_rules()
        idx = next((i for i, r in enumerate(rules) if r.get("rule_id") == rule_id), None)
        if idx is None:
            raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")
        if body.rule_id != rule_id and any(r.get("rule_id") == body.rule_id for r in rules):
            raise HTTPException(status_code=409, detail=f"Yeni rule_id zaten mevcut: {body.rule_id}")
        rules[idx] = body.model_dump()
        loaded = _write_rules_atomic(rules)
    logger.info(f"Korelasyon kuralı güncellendi: {rule_id}")
    return {"rule_id": body.rule_id, "loaded_count": loaded}


@router.delete("/correlation/rules/{rule_id}")
@limiter.limit("20/minute", key_func=_auth_key)
def delete_rule(request: Request, response: Response, rule_id: str, _: User = Depends(require_admin)):
    with _rules_lock:
        rules = _read_all_rules()
        new_rules = [r for r in rules if r.get("rule_id") != rule_id]
        if len(new_rules) == len(rules):
            raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")
        loaded = _write_rules_atomic(new_rules)
    logger.info(f"Korelasyon kuralı silindi: {rule_id}")
    return {"deleted": rule_id, "loaded_count": loaded}


@router.patch("/correlation/rules/{rule_id}/toggle")
@limiter.limit("20/minute", key_func=_auth_key)
def toggle_rule(request: Request, response: Response, rule_id: str, _: User = Depends(require_admin)):
    with _rules_lock:
        rules = _read_all_rules()
        idx = next((i for i, r in enumerate(rules) if r.get("rule_id") == rule_id), None)
        if idx is None:
            raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")
        rules[idx]["enabled"] = not rules[idx].get("enabled", True)
        loaded = _write_rules_atomic(rules)
    logger.info(f"Korelasyon kuralı toggle: {rule_id} → {rules[idx]['enabled']}")
    return {"rule_id": rule_id, "enabled": rules[idx]["enabled"], "loaded_count": loaded}


# ─── Bulk compat + ops ───────────────────────────────────────────────────────

@router.put("/correlation/rules")
@limiter.limit("20/minute", key_func=_auth_key)
def update_rules_bulk(
    request: Request,
    response: Response,
    body: RulesUpdateRequest,
    _: User = Depends(require_admin),
):
    """Korelasyon kurallarını toplu güncelle (backward compat). Her kural Pydantic ile valide edilir."""
    validated: list[dict] = []
    for i, rule in enumerate(body.rules):
        try:
            validated.append(CorrelationRuleIn(**rule).model_dump())
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Kural {i} geçersiz: {exc}")
    with _rules_lock:
        loaded = _write_rules_atomic(validated)
    logger.info(f"Korelasyon kuralları bulk güncellendi: {loaded} kural yüklendi")
    return {"saved": len(validated), "loaded": loaded}


@router.post("/correlation/run")
@limiter.limit("20/minute", key_func=_auth_key)
def run_correlation(request: Request, response: Response, _: User = Depends(get_current_user)):
    events = correlator.run()
    return {"triggered": len(events), "events": events}


@router.post("/correlation/rules/reload")
@limiter.limit("20/minute", key_func=_auth_key)
def reload_rules(request: Request, response: Response, _: User = Depends(get_current_user)):
    count = correlator.load_rules()
    return {"loaded": count, "rules": [r.rule_id for r in correlator.rules]}
