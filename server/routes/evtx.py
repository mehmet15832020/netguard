"""
NetGuard Server — EVTX Dosya Yükleme

POST /api/v1/evtx/upload  → .evtx dosyasını parse et, security event olarak kaydet
GET  /api/v1/evtx/uploads → Yükleme geçmişi
"""

import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File

from server.auth import User, get_current_user
from server.database import db
from server.evtx_parser import parse_evtx_bytes
from shared.models import SecurityEvent, SecurityEventType

router = APIRouter()
logger = logging.getLogger(__name__)

MAX_EVTX_SIZE = 50 * 1024 * 1024  # 50 MB


@router.post("/evtx/upload")
async def upload_evtx(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    if not file.filename or not file.filename.lower().endswith(".evtx"):
        raise HTTPException(status_code=400, detail="Yalnızca .evtx dosyası kabul edilir")

    data = await file.read()
    if len(data) > MAX_EVTX_SIZE:
        raise HTTPException(status_code=413, detail="Dosya 50 MB sınırını aşıyor")
    if len(data) == 0:
        raise HTTPException(status_code=400, detail="Boş dosya")

    records = parse_evtx_bytes(data)
    if not records:
        return {
            "filename": file.filename,
            "parsed":   0,
            "saved":    0,
            "message":  "Tanınan event bulunamadı (4624/4625/4688)",
        }

    hostname = file.filename.replace(".evtx", "")
    saved = 0
    for rec in records:
        try:
            event = SecurityEvent(
                event_id    = str(uuid.uuid4()),
                agent_id    = f"evtx:{current_user.username}",
                hostname    = rec.get("source_host") or hostname,
                event_type  = SecurityEventType(rec["event_type"]),
                severity    = rec["severity"],
                source_ip   = rec.get("source_ip"),
                username    = rec.get("username"),
                message     = rec["message"],
                raw_data    = rec.get("raw_data"),
                occurred_at = datetime.fromisoformat(rec["occurred_at"])
                              if rec.get("occurred_at") else datetime.now(timezone.utc),
            )
            db.save_security_event(event)
            saved += 1
        except Exception as exc:
            logger.warning(f"EVTX event kaydedilemedi: {exc}")

    db.save_audit_event(
        actor=current_user.username,
        action="evtx_uploaded",
        resource=file.filename,
        detail=f"{saved} event kaydedildi",
    )

    return {
        "filename": file.filename,
        "parsed":   len(records),
        "saved":    saved,
    }
