"""
NetGuard Server — Log endpoint'leri

GET  /api/v1/logs/normalized          → Normalize edilmiş logları listele
GET  /api/v1/logs/raw                 → Ham logları listele
POST /api/v1/logs/ingest              → Tek log manuel gönder (test/debug)
POST /api/v1/logs/firewall            → Firewall log satırı gönder (pfSense/ASA/FortiGate)
POST /api/v1/logs/firewall/batch      → Toplu firewall log gönder
POST /api/v1/logs/webserver           → Web server log satırı gönder (nginx/Apache)
POST /api/v1/logs/webserver/batch     → Toplu web server log gönder
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List

from server.auth import User, get_current_user, get_agent_from_api_key, tenant_scope
from server.database import db
from server.log_normalizer import process_and_store
from server.parsers.firewall import detect_and_parse as detect_firewall
from server.parsers.web_log import detect_and_parse as detect_weblog

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
    current_user: User = Depends(get_current_user),
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
        tenant_id=tenant_scope(current_user),
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


class FirewallLogRequest(BaseModel):
    line: str
    source_host: str = "firewall"


class FirewallBatchRequest(BaseModel):
    lines: List[str]
    source_host: str = "firewall"


@router.post("/logs/firewall", status_code=202)
def ingest_firewall_log(
    req: FirewallLogRequest,
    _: User = Depends(get_current_user),
):
    """Tek firewall log satırı al, parse et, normalize olarak kaydet."""
    norm = detect_firewall(req.line)
    if norm is None:
        return {"success": False, "message": "Tanınan firewall formatı değil"}
    if norm.source_host == norm.source_host:
        norm.source_host = req.source_host
    db.save_normalized_log(norm)
    return {"success": True, "source_type": norm.source_type, "event_type": norm.event_type}


@router.post("/logs/firewall/batch", status_code=202)
def ingest_firewall_batch(
    req: FirewallBatchRequest,
    _: User = Depends(get_current_user),
):
    """Toplu firewall log satırı al — maksimum 1000 satır."""
    if len(req.lines) > 1000:
        raise HTTPException(status_code=400, detail="Maksimum 1000 satır gönderilebilir")

    parsed = skipped = 0
    for line in req.lines:
        norm = detect_firewall(line)
        if norm:
            norm.source_host = req.source_host
            db.save_normalized_log(norm)
            parsed += 1
        else:
            skipped += 1

    return {"parsed": parsed, "skipped": skipped, "total": len(req.lines)}


class WebLogRequest(BaseModel):
    line: str
    source_host: str = "webserver"


class WebLogBatchRequest(BaseModel):
    lines: List[str]
    source_host: str = "webserver"


@router.post("/logs/webserver", status_code=202)
def ingest_webserver_log(
    req: WebLogRequest,
    _: User = Depends(get_current_user),
):
    """Tek nginx/Apache log satırı al, parse et, normalize olarak kaydet."""
    norm = detect_weblog(req.line, req.source_host)
    if norm is None:
        return {"success": False, "message": "Tanınan web log formatı değil"}
    db.save_normalized_log(norm)
    return {"success": True, "source_type": norm.source_type, "event_type": norm.event_type}


@router.post("/logs/webserver/batch", status_code=202)
def ingest_webserver_batch(
    req: WebLogBatchRequest,
    _: User = Depends(get_current_user),
):
    """Toplu nginx/Apache log satırı al — maksimum 1000 satır."""
    if len(req.lines) > 1000:
        raise HTTPException(status_code=400, detail="Maksimum 1000 satır gönderilebilir")

    parsed = skipped = 0
    for line in req.lines:
        norm = detect_weblog(line, req.source_host)
        if norm:
            db.save_normalized_log(norm)
            parsed += 1
        else:
            skipped += 1

    return {"parsed": parsed, "skipped": skipped, "total": len(req.lines)}
