import logging
import sqlite3
from datetime import datetime, timezone

from server.anomaly.models import MetricSnapshot

logger = logging.getLogger(__name__)

WINDOW_MINUTES = 5

_QUERY = f"""
SELECT
    src_ip AS entity_id,
    COUNT(*)                                                           AS total_events,
    SUM(CASE WHEN event_type = 'fw_block'                   THEN 1 ELSE 0 END) AS fw_blocks,
    SUM(CASE WHEN event_type IN ('ssh_failure','auth_fail','web_auth_fail')
                                                            THEN 1 ELSE 0 END) AS auth_failures,
    COUNT(DISTINCT dst_ip)                                             AS unique_dsts,
    COUNT(DISTINCT dst_port)                                           AS unique_ports
FROM normalized_logs
WHERE
    datetime(timestamp) >= datetime('now', '-{WINDOW_MINUTES} minutes')
    AND src_ip IS NOT NULL
    AND category = 'network'
GROUP BY src_ip
HAVING total_events >= 2
"""


class MetricsCollector:
    """
    normalized_logs tablosundan son {WINDOW_MINUTES} dakikanın
    entity (src_ip) başına metrik değerlerini toplar.
    """

    def __init__(self, db_path: str):
        self._path = db_path

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def collect(self) -> list[MetricSnapshot]:
        now = datetime.now(timezone.utc)
        try:
            with self._conn() as conn:
                rows = conn.execute(_QUERY).fetchall()
        except sqlite3.OperationalError:
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
            logger.debug(f"Metrik toplama: {len(snapshots)} entity, {WINDOW_MINUTES}dk pencere")
        return snapshots
