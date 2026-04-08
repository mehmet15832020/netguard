"""
NetGuard Server — SQLite kalıcı depolama

Alert'leri ve güvenlik event'lerini diske yazar.
InMemoryStorage ile paralel çalışır — RAM cache, SQLite kalıcılık sağlar.

Tablo şeması:
  alerts          — metric alertleri (CPU yüksek, disk dolu vb.)
  security_events — auth.log, port değişimi, checksum olayları
"""

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Optional

from shared.models import Alert, AlertSeverity, AlertStatus, SecurityEvent, SecurityEventType

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("NETGUARD_DB_PATH", "netguard.db")

_CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id     TEXT UNIQUE NOT NULL,
    agent_id     TEXT NOT NULL,
    hostname     TEXT NOT NULL,
    severity     TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',
    metric       TEXT NOT NULL,
    message      TEXT NOT NULL,
    value        REAL NOT NULL,
    threshold    REAL NOT NULL,
    triggered_at TEXT NOT NULL,
    resolved_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_agent  ON alerts(agent_id);
"""

_CREATE_SECURITY_EVENTS = """
CREATE TABLE IF NOT EXISTS security_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT UNIQUE NOT NULL,
    agent_id     TEXT NOT NULL,
    hostname     TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    severity     TEXT NOT NULL,
    source_ip    TEXT,
    username     TEXT,
    message      TEXT NOT NULL,
    raw_data     TEXT,
    occurred_at  TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sec_type    ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_sec_agent   ON security_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_sec_time    ON security_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_sec_srcip   ON security_events(source_ip);
"""


class DatabaseManager:
    """
    Thread-safe SQLite yöneticisi.
    Her işlem kendi connection'ını açar — WAL mode ile eşzamanlı okuma desteklenir.
    """

    def __init__(self, db_path: str = DB_PATH):
        self._path = db_path
        self._lock = Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Tabloları oluştur, yoksa geç."""
        with self._connect() as conn:
            conn.executescript(_CREATE_ALERTS)
            conn.executescript(_CREATE_SECURITY_EVENTS)
        logger.info(f"SQLite başlatıldı: {Path(self._path).resolve()}")

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")   # Eşzamanlı okuma/yazma
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    #  ALERTS
    # ------------------------------------------------------------------ #

    def save_alert(self, alert: Alert) -> None:
        """Alert'i kaydet. Zaten varsa status'unu güncelle."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("""
                    INSERT INTO alerts
                        (alert_id, agent_id, hostname, severity, status,
                         metric, message, value, threshold, triggered_at, resolved_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(alert_id) DO UPDATE SET
                        status      = excluded.status,
                        resolved_at = excluded.resolved_at
                """, (
                    alert.alert_id,
                    alert.agent_id,
                    alert.hostname,
                    alert.severity.value,
                    alert.status.value,
                    alert.metric,
                    alert.message,
                    alert.value,
                    alert.threshold,
                    alert.triggered_at.isoformat(),
                    alert.resolved_at.isoformat() if alert.resolved_at else None,
                ))

    def get_alerts(
        self,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> list[Alert]:
        """Alert listesini döndür. Status filtresi opsiyonel."""
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE status = ? ORDER BY triggered_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM alerts ORDER BY triggered_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [self._row_to_alert(r) for r in rows]

    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        return Alert(
            alert_id    = row["alert_id"],
            agent_id    = row["agent_id"],
            hostname    = row["hostname"],
            severity    = AlertSeverity(row["severity"]),
            status      = AlertStatus(row["status"]),
            metric      = row["metric"],
            message     = row["message"],
            value       = row["value"],
            threshold   = row["threshold"],
            triggered_at= datetime.fromisoformat(row["triggered_at"]),
            resolved_at = datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None,
        )

    # ------------------------------------------------------------------ #
    #  SECURITY EVENTS
    # ------------------------------------------------------------------ #

    def save_security_event(self, event: SecurityEvent) -> None:
        """Güvenlik olayını kaydet. Duplicate event_id'yi sessizce yoksay."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO security_events
                        (event_id, agent_id, hostname, event_type, severity,
                         source_ip, username, message, raw_data,
                         occurred_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id,
                    event.agent_id,
                    event.hostname,
                    event.event_type.value,
                    event.severity,
                    event.source_ip,
                    event.username,
                    event.message,
                    event.raw_data,
                    event.occurred_at.isoformat(),
                    event.created_at.isoformat(),
                ))

    def get_security_events(
        self,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
    ) -> list[SecurityEvent]:
        """Güvenlik olaylarını filtreli getir."""
        clauses, params = [], []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM security_events {where} ORDER BY occurred_at DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def count_recent_failures(
        self,
        source_ip: str,
        since_iso: str,
    ) -> int:
        """Belirli IP'den son X dakikadaki başarısız login sayısı."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) as cnt FROM security_events
                WHERE source_ip = ?
                  AND event_type = ?
                  AND occurred_at >= ?
                """,
                (source_ip, SecurityEventType.SSH_FAILURE.value, since_iso),
            ).fetchone()
        return row["cnt"] if row else 0

    def _row_to_event(self, row: sqlite3.Row) -> SecurityEvent:
        return SecurityEvent(
            event_id    = row["event_id"],
            agent_id    = row["agent_id"],
            hostname    = row["hostname"],
            event_type  = SecurityEventType(row["event_type"]),
            severity    = row["severity"],
            source_ip   = row["source_ip"],
            username    = row["username"],
            message     = row["message"],
            raw_data    = row["raw_data"],
            occurred_at = datetime.fromisoformat(row["occurred_at"]),
            created_at  = datetime.fromisoformat(row["created_at"]),
        )


# Global instance — uygulama boyunca tek bir tane
db = DatabaseManager()
