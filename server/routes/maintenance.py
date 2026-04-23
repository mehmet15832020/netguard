"""
NetGuard — Maintenance endpoint'leri

POST /api/v1/maintenance/cleanup  → Manuel retention cleanup (admin)
GET  /api/v1/maintenance/status   → DB tablo boyutları
"""

from fastapi import APIRouter, Depends
from server.auth import User, require_admin
from server.database import db

router = APIRouter()


@router.post("/maintenance/cleanup")
def trigger_cleanup(_: User = Depends(require_admin)):
    """Log retention cleanup'ı manuel tetikle."""
    from server.retention import run_retention
    report = run_retention()
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
                counts[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
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
