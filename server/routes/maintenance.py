"""
NetGuard — Maintenance endpoint'leri

POST /api/v1/maintenance/cleanup                   → Manuel retention cleanup (admin)
GET  /api/v1/maintenance/status                    → DB tablo boyutları
GET  /api/v1/maintenance/audit                     → Audit log (admin)
GET  /api/v1/audit-log/verify                      → SHA-256 hash zinciri bütünlük kontrolü (admin)
GET  /api/v1/maintenance/suricata-update/status    → Son kural güncelleme durumu (admin)
POST /api/v1/maintenance/suricata-update/trigger   → Manuel kural güncelleme tetikle (admin)
GET  /api/v1/maintenance/kev/status                → CISA KEV istatistik + son girişler (admin)
POST /api/v1/maintenance/kev/fetch                 → KEV feed'ini manuel çek (admin, 2/hour)
"""

import asyncio
import json
import os
import subprocess
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from server.auth import User, require_admin
from server.database import db
from server.limiter import _auth_key, limiter
from server.collectors.kev_monitor import _MONITORED_VENDORS, fetch_kev_once

_SURICATA_STATE_FILE = Path(
    os.getenv("SURICATA_UPDATE_STATE_FILE", "/var/lib/netguard/suricata_update_state.json")
)
_SURICATA_UPDATE_SCRIPT = Path(
    os.getenv("SURICATA_UPDATE_SCRIPT", "/usr/local/bin/suricata-update-cron.sh")
)

router = APIRouter()


@router.post("/maintenance/cleanup")
def trigger_cleanup(request: Request, admin: User = Depends(require_admin)):
    """Log retention cleanup'ı manuel tetikle."""
    from server.retention import run_retention
    report = run_retention()
    db.save_audit_event(
        actor=admin.username, action="retention.cleanup", resource="all_tables",
        detail=f"archived={report['total_archived']} deleted={report['total_deleted']}",
        ip_address=request.client.host if request.client else "",
    )
    return report


@router.get("/maintenance/status")
def db_status(_: User = Depends(require_admin)):
    """Tablo boyutlarını ve retention konfigürasyonunu döndür."""
    from server.retention import (
        RETAIN_NORMALIZED_DAYS, RETAIN_SECURITY_DAYS,
        RETAIN_CORRELATED_DAYS, RETAIN_ALERTS_DAYS,
        ARCHIVE_DIR, ARCHIVE_TOTAL_DAYS,
    )
    import os

    tables = [
        "normalized_logs", "security_events", "correlated_events",
        "alerts", "raw_logs", "snmp_poll_history",
    ]
    counts: dict[str, int] = {}
    with db._connect() as conn:
        for t in tables:
            try:
                counts[t] = conn.execute(f"SELECT COUNT(*) AS cnt FROM {t}").fetchone()["cnt"]
            except Exception:
                counts[t] = -1

    # Arşiv dizin boyutu
    archive_files = 0
    archive_size_mb = 0.0
    if ARCHIVE_DIR.exists():
        gz_files = list(ARCHIVE_DIR.glob("*.json.gz"))
        archive_files = len(gz_files)
        archive_size_mb = round(sum(f.stat().st_size for f in gz_files) / 1e6, 2)

    return {
        "table_counts": counts,
        "retention_policy": {
            "normalized_logs_days":  RETAIN_NORMALIZED_DAYS,
            "security_events_days":  RETAIN_SECURITY_DAYS,
            "correlated_events_days": RETAIN_CORRELATED_DAYS,
            "alerts_resolved_days":  RETAIN_ALERTS_DAYS,
            "archive_total_days":    ARCHIVE_TOTAL_DAYS,
        },
        "archive": {
            "directory": str(ARCHIVE_DIR),
            "file_count": archive_files,
            "total_size_mb": archive_size_mb,
        },
    }


@router.get("/maintenance/audit")
def audit_log(
    limit: int = Query(100, ge=1, le=1000),
    actor: str = Query(""),
    _: User = Depends(require_admin),
):
    """Admin eylem geçmişini döndür."""
    return {"events": db.get_audit_log(limit=limit, actor=actor)}


@router.get("/audit-log/verify")
@limiter.limit("2/minute", key_func=_auth_key)
async def verify_audit_log(request: Request, response: Response, _: User = Depends(require_admin)):
    """SHA-256 hash zinciri bütünlüğünü doğrula (NIST SP 800-92 §3.2)."""
    return await asyncio.to_thread(db.verify_audit_chain)


@router.get("/maintenance/suricata-update/status")
def suricata_update_status(_: User = Depends(require_admin)):
    """Son Suricata ET kural güncelleme durumunu döndür (CIS Controls v8.1 Safeguard 13.8)."""
    if not _SURICATA_STATE_FILE.exists():
        return {
            "status": "never_run",
            "last_updated": None,
            "rule_count": 0,
            "reload_status": None,
            "error": None,
            "sources": None,
        }
    try:
        return json.loads(_SURICATA_STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise HTTPException(status_code=500, detail=f"State dosyası okunamadı: {exc}") from exc


@router.post("/maintenance/suricata-update/trigger")
@limiter.limit("2/hour", key_func=_auth_key)
def trigger_suricata_update(
    request: Request,
    response: Response,
    admin: User = Depends(require_admin),
):
    """Suricata ET kural güncellemesini manuel tetikle (admin, 2/hour)."""
    if not _SURICATA_UPDATE_SCRIPT.exists():
        raise HTTPException(
            status_code=503,
            detail=f"Update script bulunamadı: {_SURICATA_UPDATE_SCRIPT}",
        )

    if _SURICATA_STATE_FILE.exists():
        try:
            state = json.loads(_SURICATA_STATE_FILE.read_text(encoding="utf-8"))
            if state.get("status") == "running":
                raise HTTPException(status_code=409, detail="Güncelleme zaten çalışıyor.")
        except (json.JSONDecodeError, OSError):
            pass

    import uuid as _uuid
    job_id = f"api-{_uuid.uuid4().hex[:8]}"

    db.save_audit_event(
        actor=admin.username,
        action="suricata_update.trigger",
        resource="suricata_rules",
        detail=f"job_id={job_id} script={_SURICATA_UPDATE_SCRIPT}",
        ip_address=request.client.host if request.client else "",
    )

    subprocess.Popen(
        [str(_SURICATA_UPDATE_SCRIPT), job_id],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    return {
        "job_id": job_id,
        "status": "started",
        "message": "Kural güncelleme başlatıldı. Durum için GET .../suricata-update/status",
    }


@router.get("/maintenance/kev/status")
def kev_status(
    limit: int = Query(20, ge=1, le=200),
    vendor: str = Query(""),
    _: User = Depends(require_admin),
):
    """CISA KEV istatistik + son girişler (CIS Controls v8.1 Safeguard 7.1)."""
    stats = db.get_kev_stats()
    entries = db.get_kev_entries(limit=limit, vendor=vendor)
    return {
        "stats":             stats,
        "monitored_vendors": sorted(_MONITORED_VENDORS),
        "entries":           entries,
    }


@router.post("/maintenance/kev/fetch")
@limiter.limit("2/hour", key_func=_auth_key)
async def trigger_kev_fetch(
    request: Request,
    response: Response,
    admin: User = Depends(require_admin),
):
    """CISA KEV feed'ini manuel çek ve DB'yi güncelle (admin, 2/hour)."""
    result = await fetch_kev_once()

    db.save_audit_event(
        actor=admin.username,
        action="kev.fetch",
        resource="kev_entries",
        detail=f"new={result.get('new_count', 0)} total={result.get('total', 0)}",
        ip_address=request.client.host if request.client else "",
    )

    if result.get("status") == "error":
        raise HTTPException(status_code=502, detail=f"KEV fetch hatası: {result.get('detail')}")

    return result
