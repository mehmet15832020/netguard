"""
NetGuard Server — Log endpoint'leri

GET  /api/v1/logs/normalized          → Normalize edilmiş logları listele
GET  /api/v1/logs/raw                 → Ham logları listele
POST /api/v1/logs/ingest              → Tek log manuel gönder (test/debug)
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from server.auth import User, get_current_user
from server.database import db
from server.log_normalizer import process_and_store

logger = logging.getLogger(__name__)
router = APIRouter()


class LogIngestRequest(BaseModel):
    raw_content: str
    source_host: str = "unknown"


@router.get("/logs/normalized")
def list_normalized_logs(
    source_type: str = None,
    category: str = None,
    src_ip: str = None,
    event_type: str = None,
    limit: int = 100,
    _: User = Depends(get_current_user),
):
    """Normalize edilmiş logları filtreli listele."""
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit 1-1000 arasında olmalı")
    logs = db.get_normalized_logs(
        source_type=source_type,
        category=category,
        src_ip=src_ip,
        event_type=event_type,
        limit=limit,
    )
    return {"count": len(logs), "logs": logs}


@router.get("/logs/raw")
def list_raw_logs(
    normalized: bool = None,
    limit: int = 100,
    _: User = Depends(get_current_user),
):
    """Ham logları listele. normalized=false ile işlenmemişleri filtrele."""
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit 1-1000 arasında olmalı")

    if normalized is False:
        logs = db.get_unnormalized_raw_logs(limit=limit)
    else:
        # Tüm ham loglar — şimdilik normalize edilmemişler
        logs = db.get_unnormalized_raw_logs(limit=limit)

    return {"count": len(logs), "logs": logs}


@router.post("/logs/ingest")
def ingest_log(
    req: LogIngestRequest,
    _: User = Depends(get_current_user),
):
    """Tek log satırını normalize edip kaydet. Test ve debug için."""
    norm = process_and_store(req.raw_content, req.source_host)
    if norm is None:
        return {"success": False, "message": "Log parse edilemedi, ham olarak kaydedildi."}
    return {"success": True, "normalized": norm}
