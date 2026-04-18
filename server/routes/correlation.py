"""
NetGuard Server — Korelasyon endpoint'leri

GET  /api/v1/correlation/events          → Korelasyon olaylarını listele
GET  /api/v1/correlation/rules           → Aktif kuralları listele
PUT  /api/v1/correlation/rules           → Kuralları güncelle ve kaydet
POST /api/v1/correlation/run             → Korelasyonu manuel tetikle
POST /api/v1/correlation/rules/reload    → Kural dosyasını yeniden yükle
"""

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from server.auth import User, get_current_user, require_admin
from server.correlator import correlator, RULES_PATH
from server.database import db

logger = logging.getLogger(__name__)
router = APIRouter()


class RulesUpdateRequest(BaseModel):
    rules: list[dict[str, Any]]


@router.get("/correlation/events")
def list_correlated_events(
    rule_id: str = None,
    severity: str = None,
    limit: int = 100,
    _: User = Depends(get_current_user),
):
    """Korelasyon olaylarını filtreli listele."""
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit 1-500 arasında olmalı")
    events = db.get_correlated_events(rule_id=rule_id, severity=severity, limit=limit)
    return {"count": len(events), "events": events}


@router.get("/correlation/rules")
def list_rules(_: User = Depends(get_current_user)):
    """Yüklü korelasyon kurallarını listele."""
    rules = [
        {
            "rule_id":          r.rule_id,
            "name":             r.name,
            "description":      r.description,
            "match_event_type": r.match_event_type,
            "group_by":         r.group_by,
            "window_seconds":   r.window_seconds,
            "threshold":        r.threshold,
            "severity":         r.severity,
            "output_event_type":r.output_event_type,
        }
        for r in correlator.rules
    ]
    return {"count": len(rules), "rules": rules}


@router.put("/correlation/rules")
def update_rules(
    request: RulesUpdateRequest,
    _: User = Depends(require_admin),
):
    """Korelasyon kurallarını güncelle, dosyaya kaydet ve yeniden yükle."""
    required_fields = {"rule_id", "name", "match_event_type", "window_seconds", "threshold", "output_event_type"}
    for i, rule in enumerate(request.rules):
        missing = required_fields - rule.keys()
        if missing:
            raise HTTPException(
                status_code=422,
                detail=f"Kural {i} eksik alan: {missing}",
            )

    path = Path(RULES_PATH)
    try:
        path.write_text(json.dumps(request.rules, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Dosya yazılamadı: {exc}")

    loaded = correlator.load_rules()
    logger.info(f"Korelasyon kuralları güncellendi: {loaded} kural yüklendi")
    return {"saved": len(request.rules), "loaded": loaded}


@router.post("/correlation/run")
def run_correlation(_: User = Depends(get_current_user)):
    """Korelasyonu şimdi çalıştır — yeni olayları döner."""
    events = correlator.run()
    return {
        "triggered": len(events),
        "events": events,
    }


@router.post("/correlation/rules/reload")
def reload_rules(_: User = Depends(get_current_user)):
    """Kural dosyasını yeniden yükle — sunucuyu yeniden başlatmaya gerek yok."""
    count = correlator.load_rules()
    return {"loaded": count, "rules": [r.rule_id for r in correlator.rules]}
