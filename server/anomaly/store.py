import json
import logging
from datetime import datetime, timezone

from server.anomaly.models import AnomalyResult
from server.database import DatabaseManager

logger = logging.getLogger(__name__)


class AnomalyResultStore:
    """PostgreSQL tabanlı anomali sonuç deposu."""

    def __init__(self, db: DatabaseManager):
        self._db = db

    def save(self, result: AnomalyResult) -> None:
        with self._db._connect() as conn:
            conn.execute(
                """
                INSERT INTO anomaly_results
                    (result_id, entity_id, metric, observed_value,
                     baseline_mean, baseline_std, z_score, severity,
                     confidence, message, detected_at, extra)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (result_id) DO NOTHING
                """,
                (
                    result.result_id,
                    result.entity_id,
                    result.metric,
                    result.observed_value,
                    result.baseline_mean,
                    result.baseline_std,
                    result.z_score,
                    result.severity,
                    result.confidence,
                    result.message,
                    result.detected_at,
                    json.dumps(result.extra),
                ),
            )

    def list_recent(
        self,
        limit: int = 100,
        entity_id: str | None = None,
        severity: str | None = None,
        since_hours: int = 24,
    ) -> list[dict]:
        conditions = [f"detected_at >= NOW() - {int(since_hours)} * INTERVAL '1 hour'"]
        params: list = []
        if entity_id:
            conditions.append("entity_id = %s")
            params.append(entity_id)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        where = " AND ".join(conditions)
        params.append(limit)
        with self._db._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM anomaly_results WHERE {where} "
                f"ORDER BY detected_at DESC LIMIT %s",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    def summary(self, since_hours: int = 24) -> dict:
        with self._db._connect() as conn:
            row = conn.execute(
                f"""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN severity = 'high'     THEN 1 ELSE 0 END) AS high,
                    SUM(CASE WHEN severity = 'warning'  THEN 1 ELSE 0 END) AS warning,
                    COUNT(DISTINCT entity_id) AS affected_entities
                FROM anomaly_results
                WHERE detected_at >= NOW() - {int(since_hours)} * INTERVAL '1 hour'
                """
            ).fetchone()
        return dict(row) if row else {}
