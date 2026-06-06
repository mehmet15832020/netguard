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
MIN_EVENTS_FOR_BASELINE       = 10   # Profil oluşturmak için minimum olay sayısı
MIN_SAMPLE_HOURS_FOR_DEVIATION = 1   # Sapma tespiti için minimum distinct saat
TRAFFIC_SPIKE_FACTOR           = 3.0  # avg * 3x → uyarı

_VALID_COLUMNS = frozenset({"destination_port", "destination_ip", "event_action", "network_protocol"})


def update_baselines(tenant_id: str = "default") -> int:
    """
    Son BASELINE_WINDOW_DAYS günün normalized_logs'undan her source_ip
    için profil hesaplar, asset_baselines tablosuna yazar.
    Döner: güncellenen asset sayısı.
    """
    since_dt = datetime.now(timezone.utc) - timedelta(days=BASELINE_WINDOW_DAYS)
    rows = db.get_log_aggregates_by_ip(since_dt, tenant_id, MIN_EVENTS_FOR_BASELINE)

    updated = 0
    for row in rows:
        ip       = row["source_ip"]
        total    = row["total_events"]
        hours    = max(row["distinct_hours"], 1)
        avg_ph   = round(total / hours, 2)

        ports     = _top_values(ip, "destination_port", since_dt, tenant_id)
        dests     = _top_values(ip, "destination_ip",   since_dt, tenant_id)
        actions   = _top_values(ip, "event_action",     since_dt, tenant_id)
        protocols = _top_values(ip, "network_protocol", since_dt, tenant_id)

        db.upsert_asset_baseline(
            source_ip             = ip,
            tenant_id             = tenant_id,
            first_seen_at         = row["first_seen"],
            last_seen_at          = row["last_seen"],
            avg_events_per_hour   = avg_ph,
            typical_ports         = ports,
            typical_destinations  = dests,
            typical_event_actions = actions,
            typical_protocols     = protocols,
            sample_hours          = hours,
        )
        updated += 1

    logger.info("Asset baseline güncellendi: %d IP, %d günlük pencere", updated, BASELINE_WINDOW_DAYS)
    return updated


def _top_values(source_ip: str, column: str, since_dt: datetime, tenant_id: str) -> list[str]:
    """Bir kolondaki en sık TOP_N değeri döner. Whitelist ile SQL injection yok."""
    if column not in _VALID_COLUMNS:
        return []
    rows = db.get_top_values_by_ip(source_ip, column, since_dt, tenant_id, TOP_N)
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

    since_dt = datetime.now(timezone.utc) - timedelta(hours=DEVIATION_WINDOW_HOURS)
    current_rows = db.get_event_counts_by_ip(since_dt, tenant_id)

    detected = 0
    for row in current_rows:
        ip    = row["source_ip"]
        count = row["event_count"]
        bl    = baselines.get(ip)
        if not bl:
            continue

        if bl["sample_hours"] < MIN_SAMPLE_HOURS_FOR_DEVIATION:
            continue

        # Trafik spike
        avg = bl["avg_events_per_hour"]
        if avg >= 1 and count > avg * TRAFFIC_SPIKE_FACTOR:
            _write_anomaly(
                source_ip    = ip,
                event_action = "asset_anomaly_detected",
                message      = (
                    f"Trafik spike: {ip} — son 1s içinde {count} olay, "
                    f"baseline ort. {avg:.1f}/saat (eşik: {TRAFFIC_SPIKE_FACTOR}x)"
                ),
                severity  = "warning",
                tenant_id = tenant_id,
            )
            detected += 1

        # Yeni port tespiti
        if bl["typical_ports"]:
            known_ports = set(bl["typical_ports"])
            current_ports = db.get_distinct_values_by_ip(ip, "destination_port", since_dt, tenant_id)
            for port in current_ports:
                if port not in known_ports:
                    _write_anomaly(
                        source_ip    = ip,
                        event_action = "new_port_detected",
                        message      = (
                            f"Yeni port: {ip} → port {port} baseline'da görülmemiş "
                            f"(bilinen portlar: {', '.join(sorted(known_ports)[:5])})"
                        ),
                        severity  = "warning",
                        tenant_id = tenant_id,
                    )
                    detected += 1

        # Yeni protokol tespiti
        if bl["typical_protocols"]:
            known_protos = set(bl["typical_protocols"])
            current_protos = db.get_distinct_values_by_ip(ip, "network_protocol", since_dt, tenant_id)
            for proto in current_protos:
                if proto not in known_protos:
                    _write_anomaly(
                        source_ip    = ip,
                        event_action = "new_protocol_detected",
                        message      = (
                            f"Yeni protokol: {ip} → {proto} baseline'da görülmemiş "
                            f"(bilinen protokoller: {', '.join(sorted(known_protos)[:5])})"
                        ),
                        severity  = "warning",
                        tenant_id = tenant_id,
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
