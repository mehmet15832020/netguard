"""
NetGuard — Log Retention Manager

Katmanlı saklama politikası (PCI DSS / ISO 27001 referans):

  Hot  (SQLite DB)  : Konfigüre edilen süre boyunca hızlı erişim
  Warm (archive/)   : Sıkıştırılmış JSON.gz, toplam 1 yıla tamamlar
  Cold              : Bu ürünün kapsamı dışı (S3, tape vb.)

Varsayılan süreler (env ile override edilebilir):
  NETGUARD_RETAIN_NORMALIZED_DAYS    = 30   (normalized_logs DB'de)
  NETGUARD_RETAIN_SECURITY_DAYS      = 90   (security_events DB'de)
  NETGUARD_RETAIN_CORRELATED_DAYS    = 365  (correlated_events DB'de)
  NETGUARD_RETAIN_ALERTS_DAYS        = 90   (resolved alerts DB'de)
  NETGUARD_ARCHIVE_DIR               = /var/lib/netguard/archive
  NETGUARD_ARCHIVE_TOTAL_DAYS        = 365  (arşivden de sil, 1 yıl sonra)
"""

import gzip
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from server.database import db

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
#  Konfigürasyon
# ------------------------------------------------------------------ #

RETAIN_NORMALIZED_DAYS  = int(os.getenv("NETGUARD_RETAIN_NORMALIZED_DAYS",  "30"))
RETAIN_SECURITY_DAYS    = int(os.getenv("NETGUARD_RETAIN_SECURITY_DAYS",    "90"))
RETAIN_CORRELATED_DAYS  = int(os.getenv("NETGUARD_RETAIN_CORRELATED_DAYS",  "365"))
RETAIN_ALERTS_DAYS      = int(os.getenv("NETGUARD_RETAIN_ALERTS_DAYS",      "90"))
ARCHIVE_DIR             = Path(os.getenv("NETGUARD_ARCHIVE_DIR", "/var/lib/netguard/archive"))
ARCHIVE_TOTAL_DAYS      = int(os.getenv("NETGUARD_ARCHIVE_TOTAL_DAYS",      "365"))

# ------------------------------------------------------------------ #
#  Arşiv yardımcıları
# ------------------------------------------------------------------ #

def _archive_path(table: str, cutoff: datetime) -> Path:
    date_str = cutoff.strftime("%Y-%m-%d")
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    return ARCHIVE_DIR / f"{table}_{date_str}.json.gz"


def _archive_rows(table: str, rows: list[dict], cutoff: datetime) -> Path:
    """Satırları JSON.gz dosyasına yaz, mevcut dosyaya ekle."""
    path = _archive_path(table, cutoff)
    existing: list[dict] = []
    if path.exists():
        with gzip.open(path, "rt", encoding="utf-8") as f:
            existing = json.load(f)
    existing.extend(rows)
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump(existing, f, default=str, ensure_ascii=False)
    return path


def _purge_old_archives() -> int:
    """ARCHIVE_TOTAL_DAYS'den eski arşiv dosyalarını sil."""
    if not ARCHIVE_DIR.exists():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=ARCHIVE_TOTAL_DAYS)
    deleted = 0
    for gz_file in ARCHIVE_DIR.glob("*.json.gz"):
        try:
            mtime = datetime.fromtimestamp(gz_file.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                gz_file.unlink()
                deleted += 1
                logger.info(f"Arşiv silindi: {gz_file.name}")
        except OSError:
            pass
    return deleted


# ------------------------------------------------------------------ #
#  Tablo bazlı temizlik fonksiyonları
# ------------------------------------------------------------------ #

def _cleanup_table(
    table: str,
    timestamp_col: str,
    retain_days: int,
    extra_where: str = "",
) -> tuple[int, int]:
    """
    1. retain_days'den eski satırları sorgula
    2. Arşivle
    3. Sil
    Döner: (arşivlenen, silinen)
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=retain_days)
    cutoff_iso = cutoff.isoformat()

    where = f"{timestamp_col} < ?"
    if extra_where:
        where += f" AND {extra_where}"

    with db._connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE {where}", (cutoff_iso,)
        ).fetchall()

    if not rows:
        return 0, 0

    row_dicts = [dict(r) for r in rows]
    archive_file = _archive_rows(table, row_dicts, cutoff)
    logger.info(f"{table}: {len(row_dicts)} kayıt arşivlendi → {archive_file.name}")

    with db._lock:
        with db._connect() as conn:
            cur = conn.execute(
                f"DELETE FROM {table} WHERE {where}", (cutoff_iso,)
            )
            deleted = cur.rowcount

    return len(row_dicts), deleted


# ------------------------------------------------------------------ #
#  Ana cleanup fonksiyonu
# ------------------------------------------------------------------ #

def run_retention() -> dict:
    """
    Tüm tabloları retention politikasına göre temizle.
    Döner: audit kaydı (tablo → {archived, deleted})
    """
    started_at = datetime.now(timezone.utc)
    report: dict = {"started_at": started_at.isoformat(), "tables": {}}

    tasks = [
        ("normalized_logs",   "timestamp",   RETAIN_NORMALIZED_DAYS,  ""),
        ("security_events",   "timestamp",   RETAIN_SECURITY_DAYS,    ""),
        ("correlated_events", "created_at",  RETAIN_CORRELATED_DAYS,  ""),
        ("alerts",            "triggered_at", RETAIN_ALERTS_DAYS,     "status='resolved'"),
    ]

    total_archived = 0
    total_deleted  = 0

    for table, col, days, extra in tasks:
        try:
            archived, deleted = _cleanup_table(table, col, days, extra)
            report["tables"][table] = {"archived": archived, "deleted": deleted}
            total_archived += archived
            total_deleted  += deleted
        except Exception as exc:
            logger.error(f"Retention hatası [{table}]: {exc}")
            report["tables"][table] = {"error": str(exc)}

    # Eski arşiv dosyalarını temizle
    purged_archives = _purge_old_archives()

    elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
    report.update({
        "total_archived": total_archived,
        "total_deleted":  total_deleted,
        "purged_archives": purged_archives,
        "elapsed_seconds": round(elapsed, 2),
        "completed_at": datetime.now(timezone.utc).isoformat(),
    })

    logger.info(
        f"Retention tamamlandı: {total_archived} arşivlendi, "
        f"{total_deleted} silindi, {purged_archives} arşiv dosyası temizlendi "
        f"({elapsed:.1f}s)"
    )
    return report
