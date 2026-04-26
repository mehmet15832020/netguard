import json
import logging
import sqlite3
from datetime import datetime, timezone

from server.anomaly.models import AnomalyResult

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS anomaly_results (
    result_id       TEXT PRIMARY KEY,
    entity_id       TEXT    NOT NULL,
    metric          TEXT    NOT NULL,
    observed_value  REAL    NOT NULL,
    baseline_mean   REAL    NOT NULL,
    baseline_std    REAL    NOT NULL,
    z_score         REAL    NOT NULL,
    severity        TEXT    NOT NULL,
    confidence      REAL    NOT NULL,
    message         TEXT    NOT NULL,
    detected_at     TEXT    NOT NULL,
    extra           TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_anom_res_entity   ON anomaly_results(entity_id);
CREATE INDEX IF NOT EXISTS idx_anom_res_detected ON anomaly_results(detected_at);
CREATE INDEX IF NOT EXISTS idx_anom_res_severity ON anomaly_results(severity);
"""


class AnomalyResultStore:
    """Anomali sonuçlarını SQLite'ta saklar."""

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

    def save(self, result: AnomalyResult) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO anomaly_results
                    (result_id, entity_id, metric, observed_value,
                     baseline_mean, baseline_std, z_score, severity,
                     confidence, message, detected_at, extra)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    result.detected_at.isoformat(),
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
        conditions = [f"datetime(detected_at) >= datetime('now', '-{since_hours} hours')"]
        params: list = []
        if entity_id:
            conditions.append("entity_id = ?")
            params.append(entity_id)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        where = " AND ".join(conditions)
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM anomaly_results WHERE {where} "
                f"ORDER BY detected_at DESC LIMIT ?",
                params + [limit],
            ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["extra"] = json.loads(d.get("extra", "{}"))
            results.append(d)
        return results

    def summary(self, since_hours: int = 24) -> dict:
        with self._conn() as conn:
            row = conn.execute(
                f"""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN severity = 'high'     THEN 1 ELSE 0 END) AS high,
                    SUM(CASE WHEN severity = 'warning'  THEN 1 ELSE 0 END) AS warning,
                    COUNT(DISTINCT entity_id) AS affected_entities
                FROM anomaly_results
                WHERE datetime(detected_at) >= datetime('now', '-{since_hours} hours')
                """
            ).fetchone()
        return dict(row) if row else {}
