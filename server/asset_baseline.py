"""
NetGuard — V1-5: Asset Baseline Engine

Her source_ip için tipik davranış profilini öğrenir.
Mevcut davranış baseline'dan belirgin sapıyorsa normalized_logs'a
asset_anomaly_detected yazar → kill chain RECON aşaması tetiklenebilir.

Güncelleme : Her 6 saatte bir (_baseline_update_loop)
Sapma kontrolü: Her ~5 dakikada bir (_baseline_deviation_loop)
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone

from server.database import db

logger = logging.getLogger(__name__)

BASELINE_WINDOW_DAYS    = 7     # Kaç günlük geçmişten profil hesaplanır
DEVIATION_WINDOW_HOURS  = 1     # Kaç saatlik mevcut pencere (sapma tespiti)
TOP_N                   = 5     # Kaç tipik değer saklanır
MIN_EVENTS_FOR_BASELINE = 10    # Profil oluşturmak için minimum olay sayısı
TRAFFIC_SPIKE_FACTOR    = 3.0   # avg * 3x → uyarı

_VALID_COLUMNS = frozenset({"destination_port", "destination_ip", "event_action"})


def update_baselines(tenant_id: str = "default") -> int:
    """
    Son BASELINE_WINDOW_DAYS günün normalized_logs'undan her source_ip
    için profil hesaplar, asset_baselines tablosuna yazar.
    Döner: güncellenen asset sayısı.
    """
    since = (datetime.now(timezone.utc) - timedelta(days=BASELINE_WINDOW_DAYS)).isoformat()

    with db._connect() as conn:
        rows = conn.execute(
            """
            SELECT
                source_ip,
                COUNT(*) AS total_events,
                COUNT(DISTINCT strftime('%Y-%m-%dT%H', timestamp)) AS distinct_hours,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM normalized_logs
            WHERE source_ip IS NOT NULL
              AND timestamp >= ?
              AND tenant_id = ?
            GROUP BY source_ip
            HAVING total_events >= ?
            """,
            (since, tenant_id, MIN_EVENTS_FOR_BASELINE),
        ).fetchall()

    updated = 0
    for row in rows:
        ip       = row["source_ip"]
        total    = row["total_events"]
        hours    = max(row["distinct_hours"], 1)
        avg_ph   = round(total / hours, 2)

        ports   = _top_values(ip, "destination_port", since, tenant_id)
        dests   = _top_values(ip, "destination_ip",   since, tenant_id)
        actions = _top_values(ip, "event_action",     since, tenant_id)

        db.upsert_asset_baseline(
            source_ip            = ip,
            tenant_id            = tenant_id,
            first_seen_at        = row["first_seen"],
            last_seen_at         = row["last_seen"],
            avg_events_per_hour  = avg_ph,
            typical_ports        = ports,
            typical_destinations = dests,
            typical_event_actions= actions,
            sample_hours         = hours,
        )
        updated += 1

    logger.info("Asset baseline güncellendi: %d IP, %d günlük pencere", updated, BASELINE_WINDOW_DAYS)
    return updated


def _top_values(source_ip: str, column: str, since: str, tenant_id: str) -> list[str]:
    """Bir kolondaki en sık TOP_N değeri döner. Whitelist ile SQL injection yok."""
    if column not in _VALID_COLUMNS:
        return []
    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT {column} AS val, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE source_ip = ?
              AND {column} IS NOT NULL
              AND timestamp >= ?
              AND tenant_id = ?
            GROUP BY {column}
            ORDER BY cnt DESC
            LIMIT {TOP_N}
            """,
            (source_ip, since, tenant_id),
        ).fetchall()
    return [str(r["val"]) for r in rows]


def check_deviations(tenant_id: str = "default") -> int:
    """
    Son DEVIATION_WINDOW_HOURS içindeki her IP'nin event sayısını
    baseline ile karşılaştırır. Trafik spike tespit edilirse
    normalized_logs'a asset_anomaly_detected kaydı yazar.
    Döner: yazılan anomali sayısı.
    """
    baselines = db.get_all_asset_baselines(tenant_id)
    if not baselines:
        return 0

    since = (datetime.now(timezone.utc) - timedelta(hours=DEVIATION_WINDOW_HOURS)).isoformat()
    with db._connect() as conn:
        current_rows = conn.execute(
            """
            SELECT source_ip, COUNT(*) AS event_count
            FROM normalized_logs
            WHERE source_ip IS NOT NULL
              AND timestamp >= ?
              AND tenant_id = ?
            GROUP BY source_ip
            """,
            (since, tenant_id),
        ).fetchall()

    detected = 0
    for row in current_rows:
        ip    = row["source_ip"]
        count = row["event_count"]
        bl    = baselines.get(ip)
        if not bl:
            continue
        avg = bl["avg_events_per_hour"]
        if avg < 1:
            continue
        if count > avg * TRAFFIC_SPIKE_FACTOR:
            _write_anomaly(
                source_ip    = ip,
                event_action = "asset_anomaly_detected",
                message      = (
                    f"Trafik spike: {ip} — son 1s içinde {count} olay, "
                    f"baseline ort. {avg:.1f}/saat (eşik: {TRAFFIC_SPIKE_FACTOR}x)"
                ),
                severity     = "warning",
                tenant_id    = tenant_id,
            )
            detected += 1

    if detected:
        logger.warning("Asset sapma tespit edildi: %d IP, tenant=%s", detected, tenant_id)
    return detected


def _write_anomaly(
    source_ip: str,
    event_action: str,
    message: str,
    severity: str,
    tenant_id: str,
) -> None:
    from shared.models import NormalizedLog, LogSourceType, LogCategory
    log = NormalizedLog(
        log_id            = str(uuid.uuid4()),
        raw_id            = str(uuid.uuid4()),
        source_type       = LogSourceType.NETGUARD,
        observer_hostname = "asset-baseline",
        timestamp         = datetime.now(timezone.utc),
        severity          = severity,
        event_category    = LogCategory.NETWORK,
        event_action      = event_action,
        source_ip         = source_ip,
        message           = message,
        tags              = ["asset_baseline", "anomaly"],
    )
    try:
        db.save_normalized_log(log, tenant_id=tenant_id)
    except Exception as exc:
        logger.error("Asset anomali kaydedilemedi [%s]: %s", source_ip, exc)
