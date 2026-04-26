"""
NetGuard — Anomaly Detection API

GET  /api/v1/anomaly/results      → Son anomali sonuçları
GET  /api/v1/anomaly/summary      → 24 saatlik özet
GET  /api/v1/anomaly/baselines    → Entity baseline listesi
GET  /api/v1/anomaly/status/{ip}  → Belirli entity'nin warm-up durumu
"""

import logging

from fastapi import APIRouter, Depends, Query

from server.auth import User, get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()

_engine = None


def set_engine(engine) -> None:
    global _engine
    _engine = engine


def _get_engine():
    if _engine is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail="Anomaly engine henüz başlatılmadı")
    return _engine


@router.get("/anomaly/results")
def get_results(
    limit:       int            = Query(100, ge=1, le=1000),
    entity_id:   str | None     = Query(None),
    severity:    str | None     = Query(None),
    since_hours: int            = Query(24, ge=1, le=720),
    _: User = Depends(get_current_user),
):
    engine = _get_engine()
    results = engine.get_recent_results(
        limit=limit,
        entity_id=entity_id,
        severity=severity,
        since_hours=since_hours,
    )
    return {"count": len(results), "results": results}


@router.get("/anomaly/summary")
def get_summary(
    since_hours: int = Query(24, ge=1, le=720),
    _: User = Depends(get_current_user),
):
    engine = _get_engine()
    return engine.get_summary(since_hours=since_hours)


@router.get("/anomaly/baselines")
def get_baselines(_: User = Depends(get_current_user)):
    engine = _get_engine()
    entities = engine.get_baselines()
    return {"count": len(entities), "entities": entities}


@router.get("/anomaly/status/{entity_id:path}")
def get_warmup_status(
    entity_id: str,
    _: User = Depends(get_current_user),
):
    engine = _get_engine()
    return engine.get_warmup_status(entity_id)
