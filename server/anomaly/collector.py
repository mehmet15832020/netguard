import logging
from datetime import datetime, timezone

from server.anomaly.models import MetricSnapshot
from server.database import DatabaseManager

logger = logging.getLogger(__name__)

WINDOW_MINUTES = 5

_QUERY = f"""
SELECT
    source_ip AS entity_id,
    COUNT(*)                                                                        AS total_events,
    SUM(CASE WHEN event_action = 'fw_block'                              THEN 1 ELSE 0 END) AS fw_blocks,
    SUM(CASE WHEN event_action IN ('ssh_failure','auth_fail','web_auth_fail')
                                                                         THEN 1 ELSE 0 END) AS auth_failures,
    COUNT(DISTINCT destination_ip)                                                  AS unique_dsts,
    COUNT(DISTINCT destination_port)                                                AS unique_ports
FROM normalized_logs
WHERE
    timestamp >= NOW() - INTERVAL '{WINDOW_MINUTES} minutes'
    AND source_ip IS NOT NULL
    AND event_category = 'network'
GROUP BY source_ip
HAVING COUNT(*) >= 2
"""


class MetricsCollector:
    """
    normalized_logs tablosundan son {WINDOW_MINUTES} dakikanın
    entity (source_ip) başına metrik değerlerini toplar.
    """

    def __init__(self, db: DatabaseManager):
        self._db = db

    def collect(self) -> list[MetricSnapshot]:
        now = datetime.now(timezone.utc)
        try:
            with self._db._connect() as conn:
                rows = conn.execute(_QUERY).fetchall()
        except Exception:
            return []

        pm = float(WINDOW_MINUTES)
        snapshots = [
            MetricSnapshot(
                entity_id         = r["entity_id"],
                window_start      = now,
                fw_block_rate     = r["fw_blocks"] / pm,
                conn_rate         = r["total_events"] / pm,
                unique_dst_ips    = float(r["unique_dsts"]),
                unique_dst_ports  = float(r["unique_ports"]),
                auth_failure_rate = r["auth_failures"] / pm,
            )
            for r in rows
        ]

        if snapshots:
            logger.debug("Metrik toplama: %d entity, %ddk pencere", len(snapshots), WINDOW_MINUTES)
        return snapshots
