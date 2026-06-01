import logging
from datetime import datetime, timezone
from typing import Optional

from server.anomaly.models import BaselinePoint
from server.database import DatabaseManager

logger = logging.getLogger(__name__)


class BaselineStore:
    """PostgreSQL tabanlı entity-metric-saat baseline deposu."""

    def __init__(self, db: DatabaseManager):
        self._db = db

    def get(self, entity_id: str, metric: str, hour: int) -> Optional[BaselinePoint]:
        with self._db._connect() as conn:
            row = conn.execute(
                "SELECT * FROM anomaly_baselines "
                "WHERE entity_id=%s AND metric=%s AND hour_bucket=%s",
                (entity_id, metric, hour),
            ).fetchone()
        if not row:
            return None
        return BaselinePoint(
            entity_id    = row["entity_id"],
            metric       = row["metric"],
            hour_bucket  = row["hour_bucket"],
            mean         = row["mean"],
            m2           = row["m2"],
            sample_count = row["sample_count"],
            last_updated = row["last_updated"],
        )

    def get_or_create(self, entity_id: str, metric: str, hour: int) -> BaselinePoint:
        bp = self.get(entity_id, metric, hour)
        return bp if bp is not None else BaselinePoint(
            entity_id   = entity_id,
            metric      = metric,
            hour_bucket = hour,
        )

    def save(self, bp: BaselinePoint) -> None:
        now = bp.last_updated or datetime.now(timezone.utc)
        with self._db._connect() as conn:
            conn.execute(
                """
                INSERT INTO anomaly_baselines
                    (entity_id, metric, hour_bucket, mean, m2, sample_count, last_updated)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (entity_id, metric, hour_bucket) DO UPDATE SET
                    mean         = EXCLUDED.mean,
                    m2           = EXCLUDED.m2,
                    sample_count = EXCLUDED.sample_count,
                    last_updated = EXCLUDED.last_updated
                """,
                (bp.entity_id, bp.metric, bp.hour_bucket,
                 bp.mean, bp.m2, bp.sample_count, now),
            )

    def list_entities(self) -> list[dict]:
        with self._db._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    entity_id,
                    COUNT(DISTINCT metric)  AS metric_count,
                    SUM(sample_count)       AS total_samples,
                    MIN(sample_count)       AS min_samples,
                    MAX(last_updated)       AS last_seen
                FROM anomaly_baselines
                GROUP BY entity_id
                ORDER BY total_samples DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def warmup_status(self, entity_id: str, min_samples: int = 20) -> dict:
        with self._db._connect() as conn:
            rows = conn.execute(
                "SELECT metric, hour_bucket, sample_count "
                "FROM anomaly_baselines WHERE entity_id=%s",
                (entity_id,),
            ).fetchall()
        if not rows:
            return {"warmed_up": False, "sample_count": 0, "needed": min_samples}
        min_sc = min(r["sample_count"] for r in rows)
        return {
            "warmed_up":    min_sc >= min_samples,
            "sample_count": min_sc,
            "needed":       min_samples,
            "progress_pct": min(100, round(min_sc / min_samples * 100)),
        }
