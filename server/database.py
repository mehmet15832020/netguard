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

from shared.models import (
    Alert, AlertSeverity, AlertStatus,
    SecurityEvent, SecurityEventType,
    RawLog, NormalizedLog, LogSourceType, LogCategory,
    CorrelatedEvent,
)

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


_CREATE_RAW_LOGS = """
CREATE TABLE IF NOT EXISTS raw_logs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_id             TEXT UNIQUE NOT NULL,
    source_type        TEXT,
    source_host        TEXT NOT NULL,
    received_at        TEXT NOT NULL,
    raw_content        TEXT NOT NULL,
    normalized         INTEGER NOT NULL DEFAULT 0,
    normalized_log_id  TEXT
);
CREATE INDEX IF NOT EXISTS idx_raw_normalized ON raw_logs(normalized);
CREATE INDEX IF NOT EXISTS idx_raw_host       ON raw_logs(source_host);
CREATE INDEX IF NOT EXISTS idx_raw_received   ON raw_logs(received_at);
"""

_CREATE_NORMALIZED_LOGS = """
CREATE TABLE IF NOT EXISTS normalized_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id       TEXT UNIQUE NOT NULL,
    raw_id       TEXT NOT NULL,
    source_type  TEXT NOT NULL,
    source_host  TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    received_at  TEXT NOT NULL,
    severity     TEXT NOT NULL,
    category     TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    src_ip       TEXT,
    dst_ip       TEXT,
    src_port     INTEGER,
    dst_port     INTEGER,
    username     TEXT,
    message      TEXT NOT NULL,
    tags         TEXT NOT NULL DEFAULT '[]',
    processed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_norm_timestamp   ON normalized_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_norm_source_type ON normalized_logs(source_type);
CREATE INDEX IF NOT EXISTS idx_norm_category    ON normalized_logs(category);
CREATE INDEX IF NOT EXISTS idx_norm_src_ip      ON normalized_logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_norm_event_type  ON normalized_logs(event_type);
"""


_CREATE_SNMP_DEVICES = """
CREATE TABLE IF NOT EXISTS snmp_devices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host       TEXT NOT NULL,
    community  TEXT NOT NULL DEFAULT 'public',
    label      TEXT NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    added_at   TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_snmp_host ON snmp_devices(host);
"""

_CREATE_API_KEYS = """
CREATE TABLE IF NOT EXISTS api_keys (
    agent_id   TEXT PRIMARY KEY,
    api_key    TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

_CREATE_CORRELATED_EVENTS = """
CREATE TABLE IF NOT EXISTS correlated_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    corr_id        TEXT UNIQUE NOT NULL,
    rule_id        TEXT NOT NULL,
    rule_name      TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    severity       TEXT NOT NULL,
    group_value    TEXT NOT NULL,
    matched_count  INTEGER NOT NULL,
    window_seconds INTEGER NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    message        TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_corr_rule_id     ON correlated_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_corr_event_type  ON correlated_events(event_type);
CREATE INDEX IF NOT EXISTS idx_corr_group_value ON correlated_events(group_value);
CREATE INDEX IF NOT EXISTS idx_corr_created_at  ON correlated_events(created_at);
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
            conn.executescript(_CREATE_RAW_LOGS)
            conn.executescript(_CREATE_NORMALIZED_LOGS)
            conn.executescript(_CREATE_CORRELATED_EVENTS)
            conn.executescript(_CREATE_SNMP_DEVICES)
            conn.executescript(_CREATE_API_KEYS)
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


    # ------------------------------------------------------------------ #
    #  RAW LOGS
    # ------------------------------------------------------------------ #

    def save_raw_log(self, raw: RawLog) -> None:
        """Ham logu kaydet."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO raw_logs
                        (raw_id, source_type, source_host, received_at,
                         raw_content, normalized, normalized_log_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    raw.raw_id,
                    raw.source_type.value if raw.source_type else None,
                    raw.source_host,
                    raw.received_at.isoformat(),
                    raw.raw_content,
                    int(raw.normalized),
                    raw.normalized_log_id,
                ))

    def mark_raw_normalized(self, raw_id: str, normalized_log_id: str) -> None:
        """Ham logu normalize edildi olarak işaretle."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE raw_logs SET normalized=1, normalized_log_id=? WHERE raw_id=?",
                    (normalized_log_id, raw_id),
                )

    def get_unnormalized_raw_logs(self, limit: int = 100) -> list[RawLog]:
        """Henüz normalize edilmemiş ham logları getir."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM raw_logs WHERE normalized=0 ORDER BY received_at ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_raw_log(r) for r in rows]

    def _row_to_raw_log(self, row: sqlite3.Row) -> RawLog:
        return RawLog(
            raw_id            = row["raw_id"],
            source_type       = LogSourceType(row["source_type"]) if row["source_type"] else None,
            source_host       = row["source_host"],
            received_at       = datetime.fromisoformat(row["received_at"]),
            raw_content       = row["raw_content"],
            normalized        = bool(row["normalized"]),
            normalized_log_id = row["normalized_log_id"],
        )

    # ------------------------------------------------------------------ #
    #  NORMALIZED LOGS
    # ------------------------------------------------------------------ #

    def save_normalized_log(self, log: NormalizedLog) -> None:
        """Normalize edilmiş logu kaydet."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO normalized_logs
                        (log_id, raw_id, source_type, source_host, timestamp,
                         received_at, severity, category, event_type,
                         src_ip, dst_ip, src_port, dst_port,
                         username, message, tags, processed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    log.log_id,
                    log.raw_id,
                    log.source_type.value,
                    log.source_host,
                    log.timestamp.isoformat(),
                    log.received_at.isoformat(),
                    log.severity,
                    log.category.value,
                    log.event_type,
                    log.src_ip,
                    log.dst_ip,
                    log.src_port,
                    log.dst_port,
                    log.username,
                    log.message,
                    json.dumps(log.tags),
                    log.processed_at.isoformat(),
                ))

    def get_normalized_logs(
        self,
        source_type: Optional[str] = None,
        category: Optional[str] = None,
        src_ip: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> list[NormalizedLog]:
        """Normalize logları filtreli getir — timestamp'e göre sıralı."""
        clauses, params = [], []
        if source_type:
            clauses.append("source_type = ?")
            params.append(source_type)
        if category:
            clauses.append("category = ?")
            params.append(category)
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM normalized_logs {where} ORDER BY timestamp DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._row_to_normalized_log(r) for r in rows]

    def get_normalized_logs_in_window(
        self,
        event_type_prefix: str,
        group_by: str,
        group_value: str,
        since_iso: str,
        severity: Optional[str] = None,
    ) -> list[NormalizedLog]:
        """
        Korelasyon için: belirli zaman penceresindeki eşleşen normalize logları getir.
        event_type_prefix ile LIKE sorgusu yapılır (örn. 'wazuh_rule_' her wazuh kuralını yakalar).
        """
        group_col = "src_ip" if group_by == "src_ip" else "source_host"
        params = [f"{event_type_prefix}%", group_value, since_iso]
        severity_clause = ""
        if severity:
            severity_clause = "AND severity = ?"
            params.append(severity)

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM normalized_logs
                WHERE event_type LIKE ?
                  AND {group_col} = ?
                  AND timestamp >= ?
                  {severity_clause}
                ORDER BY timestamp ASC
                """,
                params,
            ).fetchall()
        return [self._row_to_normalized_log(r) for r in rows]

    def _row_to_normalized_log(self, row: sqlite3.Row) -> NormalizedLog:
        return NormalizedLog(
            log_id       = row["log_id"],
            raw_id       = row["raw_id"],
            source_type  = LogSourceType(row["source_type"]),
            source_host  = row["source_host"],
            timestamp    = datetime.fromisoformat(row["timestamp"]),
            received_at  = datetime.fromisoformat(row["received_at"]),
            severity     = row["severity"],
            category     = LogCategory(row["category"]),
            event_type   = row["event_type"],
            src_ip       = row["src_ip"],
            dst_ip       = row["dst_ip"],
            src_port     = row["src_port"],
            dst_port     = row["dst_port"],
            username     = row["username"],
            message      = row["message"],
            tags         = json.loads(row["tags"]),
            processed_at = datetime.fromisoformat(row["processed_at"]),
        )


    # ------------------------------------------------------------------ #
    #  CORRELATED EVENTS
    # ------------------------------------------------------------------ #

    def save_correlated_event(self, event: CorrelatedEvent) -> bool:
        """
        Korelasyon olayını kaydet.
        Aynı rule_id + group_value kombinasyonu son window_seconds içinde zaten varsa
        kaydetme (duplicate önleme). True döner kayıt yapıldıysa, False = atlandı.
        """
        with self._lock:
            with self._connect() as conn:
                existing = conn.execute(
                    """
                    SELECT corr_id FROM correlated_events
                    WHERE rule_id = ? AND group_value = ?
                      AND created_at >= datetime('now', ? || ' seconds')
                    LIMIT 1
                    """,
                    (event.rule_id, event.group_value, f"-{event.window_seconds}"),
                ).fetchone()

                if existing:
                    return False

                conn.execute("""
                    INSERT INTO correlated_events
                        (corr_id, rule_id, rule_name, event_type, severity,
                         group_value, matched_count, window_seconds,
                         first_seen, last_seen, message, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.corr_id,
                    event.rule_id,
                    event.rule_name,
                    event.event_type,
                    event.severity,
                    event.group_value,
                    event.matched_count,
                    event.window_seconds,
                    event.first_seen.isoformat(),
                    event.last_seen.isoformat(),
                    event.message,
                    event.created_at.isoformat(),
                ))
                return True

    def get_correlated_events(
        self,
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> list[CorrelatedEvent]:
        """Korelasyon olaylarını filtreli getir — en yeni önce."""
        clauses, params = [], []
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM correlated_events {where} ORDER BY created_at DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._row_to_correlated_event(r) for r in rows]

    def _row_to_correlated_event(self, row: sqlite3.Row) -> CorrelatedEvent:
        return CorrelatedEvent(
            corr_id        = row["corr_id"],
            rule_id        = row["rule_id"],
            rule_name      = row["rule_name"],
            event_type     = row["event_type"],
            severity       = row["severity"],
            group_value    = row["group_value"],
            matched_count  = row["matched_count"],
            window_seconds = row["window_seconds"],
            first_seen     = datetime.fromisoformat(row["first_seen"]),
            last_seen      = datetime.fromisoformat(row["last_seen"]),
            message        = row["message"],
            created_at     = datetime.fromisoformat(row["created_at"]),
        )


    # ------------------------------------------------------------------ #
    #  SNMP DEVICES
    # ------------------------------------------------------------------ #

    def add_snmp_device(self, host: str, community: str = "public", label: str = "") -> bool:
        """
        SNMP cihazı ekle. Zaten varsa False döner.
        Başarıyla eklenirse True döner.
        """
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute(
                        "INSERT INTO snmp_devices (host, community, label, enabled, added_at) VALUES (?, ?, ?, 1, ?)",
                        (host, community, label, datetime.now(timezone.utc).isoformat()),
                    )
                    return True
                except sqlite3.IntegrityError:
                    return False

    def get_snmp_devices(self, enabled_only: bool = True) -> list[dict]:
        """SNMP cihaz listesini döndür."""
        with self._connect() as conn:
            if enabled_only:
                rows = conn.execute(
                    "SELECT host, community, label, enabled, added_at FROM snmp_devices WHERE enabled=1 ORDER BY added_at"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT host, community, label, enabled, added_at FROM snmp_devices ORDER BY added_at"
                ).fetchall()
        return [dict(r) for r in rows]

    def remove_snmp_device(self, host: str) -> bool:
        """SNMP cihazını sil. Bulunursa True döner."""
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute("DELETE FROM snmp_devices WHERE host=?", (host,))
                return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    #  API KEYS
    # ------------------------------------------------------------------ #

    def save_api_key(self, agent_id: str, api_key: str) -> None:
        """Agent API key'ini kaydet veya güncelle."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO api_keys (agent_id, api_key, created_at) VALUES (?,?,?)",
                    (agent_id, api_key, now),
                )

    def get_api_key(self, agent_id: str) -> Optional[str]:
        """Agent'ın kayıtlı API key'ini döndür, yoksa None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT api_key FROM api_keys WHERE agent_id=?", (agent_id,)
            ).fetchone()
            return row["api_key"] if row else None

    def get_all_api_keys(self) -> dict[str, str]:
        """Tüm agent_id → api_key eşlemesini döndür."""
        with self._connect() as conn:
            rows = conn.execute("SELECT agent_id, api_key FROM api_keys").fetchall()
            return {row["agent_id"]: row["api_key"] for row in rows}


# Global instance — uygulama boyunca tek bir tane
db = DatabaseManager()
