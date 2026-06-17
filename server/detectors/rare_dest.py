"""NetGuard — Rare External Destination Detector (I3)"""

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from server.database import db
from shared.models import LogCategory, LogSourceType, NormalizedLog

logger = logging.getLogger(__name__)

_PRIVATE_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "169.254.", "::1", "fc", "fd", "fe80",
)

_LOOKBACK_HOURS = int(os.getenv("RARE_DEST_LOOKBACK_HOURS", "24"))
_ENABLED = os.getenv("RARE_DEST_DETECTOR", "true").lower() == "true"


def _is_external(ip: Optional[str]) -> bool:
    if not ip:
        return False
    return not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def detect_rare_external_destinations(
    new_logs: list[NormalizedLog],
    tenant_id: str = "default",
) -> list[NormalizedLog]:
    """
    Son 24 saatte görülmemiş harici IP'ye bağlantıyı tespit eder.
    DB'ye tek toplu sorguyla gider — yük minimize edilir.
    """
    if not _ENABLED or not new_logs:
        return []

    candidates = [
        log for log in new_logs
        if log.source_ip and log.destination_ip and _is_external(log.destination_ip)
    ]
    if not candidates:
        return []

    since = datetime.now(timezone.utc) - timedelta(hours=_LOOKBACK_HOURS)
    unique_srcs = list({log.source_ip for log in candidates})

    try:
        known = db.get_known_destination_ips(
            source_ips=unique_srcs,
            since=since,
            tenant_id=tenant_id,
        )
    except Exception as exc:
        logger.debug("Rare dest DB sorgusu başarısız: %s", exc)
        return []

    alerts: list[NormalizedLog] = []
    for log in candidates:
        known_dsts = known.get(log.source_ip, set())
        if log.destination_ip in known_dsts:
            continue
        alert = NormalizedLog(
            log_id=str(uuid.uuid4()),
            raw_id=str(uuid.uuid4()),
            source_type=LogSourceType.NETFLOW,
            observer_hostname=log.observer_hostname or "netguard",
            timestamp=log.timestamp,
            received_at=log.received_at,
            severity="warning",
            event_category=LogCategory.NETWORK,
            event_action="rare_external_destination",
            source_ip=log.source_ip,
            destination_ip=log.destination_ip,
            destination_port=log.destination_port,
            network_protocol=log.network_protocol,
            message=(
                f"Nadir harici bağlantı: {log.source_ip} → {log.destination_ip}"
                + (f":{log.destination_port}" if log.destination_port else "")
            ),
            tags=["rare_dest", "behavioral"],
            extra={"lookback_hours": _LOOKBACK_HOURS},
        )
        alerts.append(alert)

    return alerts
