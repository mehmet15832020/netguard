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
import re
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from server.auth import User, get_current_user, require_admin, tenant_scope
from server.correlator import correlator, RULES_PATH
from server.database import db

logger = logging.getLogger(__name__)
router = APIRouter()

# ─── Sabitler ────────────────────────────────────────────────────────────────

_VALID_GROUP_COLS = frozenset({
    "source_ip", "destination_ip", "observer_hostname", "username",
    "hostname", "event_action", "event_category", "tenant_id",
    "source_type", "network_protocol", "source_port", "destination_port",
})
_VALID_SEVERITIES = frozenset({"info", "warning", "high", "critical"})
_RULE_ID_RE = re.compile(r"^[a-z0-9_]{2,64}$")


# ─── Yardımcılar ─────────────────────────────────────────────────────────────

def _read_all_rules() -> list[dict]:
    """JSON dosyasından tüm kuralları oku (disabled dahil)."""
    try:
        return json.loads(Path(RULES_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail=f"Kural dosyası okunamadı: {exc}")


def _write_rules(rules: list[dict]) -> int:
    """Kuralları dosyaya yaz, correlator'ı yeniden yükle. Yüklenen kural sayısını döner."""
    try:
        Path(RULES_PATH).write_text(
            json.dumps(rules, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Dosya yazılamadı: {exc}")
    return correlator.load_rules()


# ─── Pydantic modeller ────────────────────────────────────────────────────────

class CorrelationRuleIn(BaseModel):
    rule_id:             str
    name:                str                   = Field(min_length=2, max_length=120)
    description:         str                   = ""
    match_event_action:  str                   = ""
    group_by:            str                   = "source_ip"
    distinct_by:         Optional[str]         = None
    window_seconds:      int                   = Field(ge=10, le=86400)
    threshold:           int                   = Field(ge=1, le=10000)
    severity:            str
    output_event_action: str                   = Field(min_length=2, max_length=120)
    enabled:             bool                  = True
    match_severity:      Optional[str]         = None
    keywords:            Optional[list[str]]   = None
    tags:                list[str]             = []

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
    """Tüm korelasyon kurallarını listele (disabled dahil, dosyadan okur)."""
    rules = _read_all_rules()
    return {"count": len(rules), "rules": rules}


@router.get("/correlation/rules/{rule_id}")
def get_rule(rule_id: str, _: User = Depends(get_current_user)):
    """Tek bir korelasyon kuralı detayını getir."""
    rules = _read_all_rules()
    rule = next((r for r in rules if r.get("rule_id") == rule_id), None)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")
    return rule


@router.post("/correlation/rules", status_code=201)
def create_rule(body: CorrelationRuleIn, _: User = Depends(require_admin)):
    """Yeni korelasyon kuralı oluştur."""
    rules = _read_all_rules()
    if any(r.get("rule_id") == body.rule_id for r in rules):
        raise HTTPException(status_code=409, detail=f"rule_id zaten mevcut: {body.rule_id}")
    rules.append(body.model_dump())
    loaded = _write_rules(rules)
    logger.info(f"Korelasyon kuralı oluşturuldu: {body.rule_id}")
    return {"rule_id": body.rule_id, "loaded_count": loaded}


@router.put("/correlation/rules/{rule_id}")
def update_rule(rule_id: str, body: CorrelationRuleIn, _: User = Depends(require_admin)):
    """Mevcut bir korelasyon kuralını güncelle."""
    rules = _read_all_rules()
    idx = next((i for i, r in enumerate(rules) if r.get("rule_id") == rule_id), None)
    if idx is None:
        raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")
    if body.rule_id != rule_id and any(r.get("rule_id") == body.rule_id for r in rules):
        raise HTTPException(status_code=409, detail=f"Yeni rule_id zaten mevcut: {body.rule_id}")
    rules[idx] = body.model_dump()
    loaded = _write_rules(rules)
    logger.info(f"Korelasyon kuralı güncellendi: {rule_id}")
    return {"rule_id": body.rule_id, "loaded_count": loaded}


@router.delete("/correlation/rules/{rule_id}")
def delete_rule(rule_id: str, _: User = Depends(require_admin)):
    """Korelasyon kuralını sil."""
    rules = _read_all_rules()
    new_rules = [r for r in rules if r.get("rule_id") != rule_id]
    if len(new_rules) == len(rules):
        raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")
    loaded = _write_rules(new_rules)
    logger.info(f"Korelasyon kuralı silindi: {rule_id}")
    return {"deleted": rule_id, "loaded_count": loaded}


@router.patch("/correlation/rules/{rule_id}/toggle")
def toggle_rule(rule_id: str, _: User = Depends(require_admin)):
    """Kuralı aktif/pasif yap."""
    rules = _read_all_rules()
    idx = next((i for i, r in enumerate(rules) if r.get("rule_id") == rule_id), None)
    if idx is None:
        raise HTTPException(status_code=404, detail=f"Kural bulunamadı: {rule_id}")
    rules[idx]["enabled"] = not rules[idx].get("enabled", True)
    loaded = _write_rules(rules)
    logger.info(f"Korelasyon kuralı toggle: {rule_id} → {rules[idx]['enabled']}")
    return {"rule_id": rule_id, "enabled": rules[idx]["enabled"], "loaded_count": loaded}


# ─── Bulk compat + ops ───────────────────────────────────────────────────────

@router.put("/correlation/rules")
def update_rules_bulk(
    request: RulesUpdateRequest,
    _: User = Depends(require_admin),
):
    """Korelasyon kurallarını toplu güncelle (backward compat)."""
    required = {"rule_id", "name", "match_event_action", "window_seconds", "threshold", "output_event_action"}
    for i, rule in enumerate(request.rules):
        missing = required - rule.keys()
        if missing:
            raise HTTPException(status_code=422, detail=f"Kural {i} eksik alan: {missing}")
    path = Path(RULES_PATH)
    try:
        path.write_text(json.dumps(request.rules, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Dosya yazılamadı: {exc}")
    loaded = correlator.load_rules()
    logger.info(f"Korelasyon kuralları bulk güncellendi: {loaded} kural yüklendi")
    return {"saved": len(request.rules), "loaded": loaded}


@router.post("/correlation/run")
def run_correlation(_: User = Depends(get_current_user)):
    events = correlator.run()
    return {"triggered": len(events), "events": events}


@router.post("/correlation/rules/reload")
def reload_rules(_: User = Depends(get_current_user)):
    count = correlator.load_rules()
    return {"loaded": count, "rules": [r.rule_id for r in correlator.rules]}
