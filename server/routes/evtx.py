"""
NetGuard Server — EVTX Dosya Yükleme

POST /api/v1/evtx/upload  → .evtx dosyasını parse et, security event + normalized log kaydet
GET  /api/v1/evtx/events  → evtx yükleme ile kaydedilen Windows security event'leri listele
"""

import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request, Response

from server.auth import User, get_current_user, tenant_scope
from server.limiter import limiter, _auth_key
from server.database import db
from server.evtx_parser import parse_evtx_bytes
from server.log_store import log_store
from server.parsers.windows import to_normalized_log
from shared.models import SecurityEvent, SecurityEventType

router = APIRouter()
logger = logging.getLogger(__name__)

MAX_EVTX_SIZE = 50 * 1024 * 1024  # 50 MB

_KNOWN_WIN_TYPES: list[str] = [
    "windows_logon_success", "windows_logon_failure", "windows_explicit_logon",
    "windows_process_create", "windows_user_created", "windows_group_member_added",
    "windows_kerberos_tgt", "windows_kerberos_service",
    "windows_sysmon_process", "windows_sysmon_network",
    "windows_sysmon_proc_access", "windows_sysmon_dns",
]


@router.post("/evtx/upload")
@limiter.limit("10/minute", key_func=_auth_key)
async def upload_evtx(
    request: Request,
    response: Response,
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
            "message":  "Tanınan event bulunamadı",
        }

    hostname   = file.filename.replace(".evtx", "")
    tenant_id  = current_user.tenant_id or "default"
    saved_sec  = 0
    saved_norm = 0

    for rec in records:
        rec_hostname = rec.get("observer_hostname") or hostname

        # ── security_events tablosu (legacy frontend listing) ─────────────────
        try:
            event = SecurityEvent(
                event_id     = str(uuid.uuid4()),
                agent_id     = f"evtx:{current_user.username}",
                hostname     = rec_hostname,
                event_action = SecurityEventType(rec["event_action"]),
                severity     = rec["severity"],
                source_ip    = rec.get("source_ip"),
                username     = rec.get("username"),
                message      = rec["message"],
                raw_data     = rec.get("raw_data"),
                occurred_at  = (
                    datetime.fromisoformat(rec["occurred_at"])
                    if rec.get("occurred_at")
                    else datetime.now(timezone.utc)
                ),
            )
            db.save_security_event(event, tenant_id=tenant_id)
            saved_sec += 1
        except ValueError:
            # Yeni Sysmon event türleri SecurityEventType enum'unda henüz yoksa atla
            logger.debug("SecurityEvent enum miss: %s — sadece normalized_log'a yazıldı", rec.get("event_action"))
        except Exception as exc:
            logger.warning("EVTX security event kaydedilemedi: %s", exc)

        # ── normalized_logs → correlator → kill chain ─────────────────────────
        norm = to_normalized_log(rec)
        if norm:
            try:
                log_store.save(norm, tenant_id=tenant_id)
                saved_norm += 1
            except Exception as exc:
                logger.warning("EVTX normalized log kaydedilemedi: %s", exc)

    db.save_audit_event(
        actor=current_user.username,
        action="evtx_uploaded",
        resource=file.filename,
        detail=f"{saved_norm} normalized log, {saved_sec} security event kaydedildi",
    )

    return {
        "filename":      file.filename,
        "parsed":        len(records),
        "saved":         saved_sec,
        "normalized":    saved_norm,
    }


@router.get("/evtx/events")
def list_evtx_events(
    event_action: str | None = None,
    limit: int = 200,
    current_user: User = Depends(get_current_user),
):
    """Windows EVTX yükleme kaynaklı security event'leri döner."""
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=400, detail="limit 1-1000 arasında olmalı")
    tid = tenant_scope(current_user)

    if event_action:
        if event_action not in _KNOWN_WIN_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"Geçerli tipler: {_KNOWN_WIN_TYPES}",
            )
        events = db.get_security_events(event_action=event_action, limit=limit, tenant_id=tid)
    else:
        legacy_types = [
            "windows_logon_success",
            "windows_logon_failure",
            "windows_process_create",
        ]
        events = []
        for wt in legacy_types:
            events.extend(db.get_security_events(event_action=wt, limit=limit, tenant_id=tid))
        events.sort(key=lambda e: e.occurred_at, reverse=True)
        events = events[:limit]

    return {"count": len(events), "events": [e.model_dump() for e in events]}
