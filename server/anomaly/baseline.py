import logging
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from server.anomaly.models import BaselinePoint

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS anomaly_baselines (
    entity_id    TEXT    NOT NULL,
    metric       TEXT    NOT NULL,
    hour_bucket  INTEGER NOT NULL,
    mean         REAL    NOT NULL DEFAULT 0.0,
    m2           REAL    NOT NULL DEFAULT 0.0,
    sample_count INTEGER NOT NULL DEFAULT 0,
    last_updated TEXT    NOT NULL,
    PRIMARY KEY (entity_id, metric, hour_bucket)
);
CREATE INDEX IF NOT EXISTS idx_anom_bl_entity ON anomaly_baselines(entity_id);
"""


class BaselineStore:
    """SQLite tabanlı entity-metric-saat baseline deposu."""

    def __init__(self, db_path: str):
        self._path = db_path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._conn() as conn:
            for stmt in _DDL.strip().split(";"):
                s = stmt.strip()
                if s:
                    conn.execute(s)

    def get(self, entity_id: str, metric: str, hour: int) -> Optional[BaselinePoint]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM anomaly_baselines "
                "WHERE entity_id=? AND metric=? AND hour_bucket=?",
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
            last_updated = datetime.fromisoformat(row["last_updated"]),
        )

    def get_or_create(self, entity_id: str, metric: str, hour: int) -> BaselinePoint:
        bp = self.get(entity_id, metric, hour)
        return bp if bp is not None else BaselinePoint(
            entity_id   = entity_id,
            metric      = metric,
            hour_bucket = hour,
        )

    def save(self, bp: BaselinePoint) -> None:
        now = (bp.last_updated or datetime.now(timezone.utc)).isoformat()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO anomaly_baselines
                    (entity_id, metric, hour_bucket, mean, m2, sample_count, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(entity_id, metric, hour_bucket) DO UPDATE SET
                    mean         = excluded.mean,
                    m2           = excluded.m2,
                    sample_count = excluded.sample_count,
                    last_updated = excluded.last_updated
                """,
                (bp.entity_id, bp.metric, bp.hour_bucket,
                 bp.mean, bp.m2, bp.sample_count, now),
            )

    def list_entities(self) -> list[dict]:
        """Tüm entity'leri baseline özeti ile döndür."""
        with self._conn() as conn:
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
        """Entity'nin warm-up durumunu döndür."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT metric, hour_bucket, sample_count "
                "FROM anomaly_baselines WHERE entity_id=?",
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
