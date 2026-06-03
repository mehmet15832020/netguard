"""
NetGuard Server — PostgreSQL + TimescaleDB kalıcı depolama

CONNECTION: psycopg3 ConnectionPool
SCHEMA:     Alembic migrations ile yönetilir (alembic upgrade head)
HYPERTABLE: normalized_logs → TimescaleDB (received_at partition key)
"""

import json
import logging
import os
import re
import uuid as _uuid_mod
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from shared.models import (
    Alert, AlertSeverity, AlertStatus,
    SecurityEvent, SecurityEventType,
    RawLog, NormalizedLog, LogSourceType, LogCategory,
    CorrelatedEvent, ParseStatus,
)

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://netguard:netguard_dev@localhost:5432/netguard",
)

_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){1,3}$')

# f-string SQL içeren metodlar için module-level whitelist'ler (OWASP SQLi Prevention)
_VALID_GROUP_COLS: frozenset[str] = frozenset({
    "source_ip", "destination_ip", "observer_hostname", "username", "hostname",
    "event_action", "event_category", "tenant_id", "source_type",
    "network_protocol", "source_port", "destination_port", "device_id",
})
_VALID_COUNT_EXPRS: frozenset[str] = frozenset(
    {"COUNT(*)"} | {f"COUNT(DISTINCT {col})" for col in _VALID_GROUP_COLS}
)
_VALID_TOP_VALUE_COLS: frozenset[str] = frozenset({"destination_port", "destination_ip", "event_action"})
_RETENTION_ALLOWED: dict[str, str] = {
    "normalized_logs":   "timestamp",
    "raw_logs":          "received_at",
    "security_events":   "occurred_at",
    "correlated_events": "created_at",
    "alerts":            "triggered_at",
}

_AUDIT_CHAIN_GENESIS = "0" * 64
_AUDIT_CHAIN_LOCK_ID = 0x41554443  # "AUDC" — audit chain serialization lock


def _audit_content(
    event_id: str, actor: str, action: str, resource: str,
    detail: str, ip_address: str, timestamp_str: str, previous_hash: str,
) -> str:
    """JSON canonical hash input — OWASP Log Forging mitigation, NIST SP 800-92 §3.2."""
    return json.dumps({
        "action": action,
        "actor": actor,
        "detail": detail,
        "event_id": event_id,
        "ip_address": ip_address,
        "previous_hash": previous_hash,
        "resource": resource,
        "timestamp": timestamp_str,
    }, sort_keys=True, separators=(",", ":"))


def _dt(val) -> datetime:
    """str veya datetime → timezone-aware datetime."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    dt = datetime.fromisoformat(str(val))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class DatabaseManager:
    """
    PostgreSQL + TimescaleDB veritabanı yöneticisi.
    SQLite DatabaseManager ile birebir aynı public interface.
    """

    _VALID_LOG_GROUP_FIELDS: frozenset = frozenset({
        "source_ip", "destination_ip", "observer_hostname",
        "username", "device_id",
    })
    _SEV_ORDER = {"info": 1, "warning": 2, "critical": 3}

    def __init__(self, url: str = DATABASE_URL):
        self._pool = ConnectionPool(
            conninfo=url,
            min_size=2,
            max_size=10,
            kwargs={"row_factory": dict_row, "options": "-c timezone=UTC"},
            open=False,
        )
        self._pool.open(wait=True)
        try:
            self.ensure_default_tenant()
        except Exception as exc:
            logger.warning("DB init: %s — Alembic migration çalışmamış olabilir", exc)
        self._check_hypertable_schema()
        logger.info("PostgreSQL bağlantı havuzu açıldı: %s", url.split("@")[-1])

    def _check_hypertable_schema(self) -> None:
        """Migration 013 çalıştırılmadıysa ON CONFLICT uyumsuzluğunu startup'ta yakala."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT indexdef FROM pg_indexes "
                    "WHERE tablename = 'normalized_logs' AND indexname = 'idx_norm_log_id'"
                ).fetchone()
                if row and "received_at" not in row["indexdef"].lower():
                    logger.error(
                        "normalized_logs.idx_norm_log_id partition-uyumsuz (sadece log_id). "
                        "save_normalized_log() ON CONFLICT hatası üretir. "
                        "Çözüm: 'alembic upgrade head' (Migration 013) çalıştırın."
                    )
        except Exception:
            pass

    @contextmanager
    def _connect(self):
        with self._pool.connection() as conn:
            yield conn

    def get_schema_version(self) -> int:
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM alembic_version"
                ).fetchone()
                return int(row["cnt"]) if row else 0
        except Exception as exc:
            logger.debug("get_schema_version başarısız: %s", exc)
            return 0

    # ------------------------------------------------------------------ #
    #  ALERTS
    # ------------------------------------------------------------------ #

    def save_alert(self, alert: Alert) -> None:
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO alerts
                    (alert_id, agent_id, hostname, severity, status,
                     metric, message, value, threshold, triggered_at, resolved_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (alert_id) DO UPDATE SET
                    status      = EXCLUDED.status,
                    resolved_at = EXCLUDED.resolved_at
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
                alert.triggered_at,
                alert.resolved_at,
            ))

    def get_alerts(
        self,
        status: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list[Alert]:
        clauses, params = [], []
        if status:
            clauses.append("status = %s"); params.append(status)
        if agent_id is not None:
            clauses.append("agent_id = %s"); params.append(agent_id)
        if tenant_id is not None:
            clauses.append("tenant_id = %s"); params.append(tenant_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY triggered_at DESC LIMIT %s",
                params,
            ).fetchall()
        return [self._row_to_alert(r) for r in rows]

    def _row_to_alert(self, row: dict) -> Alert:
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
            triggered_at= _dt(row["triggered_at"]),
            resolved_at = _dt(row["resolved_at"]),
        )

    def resolve_all_alerts(self, tenant_id: str = "default") -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE alerts SET status='resolved', resolved_at=%s WHERE status='active' AND tenant_id=%s",
                (_now(), tenant_id),
            )
            return cur.rowcount

    # ------------------------------------------------------------------ #
    #  SECURITY EVENTS
    # ------------------------------------------------------------------ #

    def save_security_event(self, event: SecurityEvent, tenant_id: str = "default") -> None:
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO security_events
                    (event_id, agent_id, hostname, event_action, severity,
                     source_ip, username, message, raw_data,
                     occurred_at, created_at, tenant_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (event_id) DO NOTHING
            """, (
                event.event_id,
                event.agent_id,
                event.hostname,
                event.event_action.value,
                event.severity,
                event.source_ip,
                event.username,
                event.message,
                event.raw_data,
                event.occurred_at,
                event.created_at,
                tenant_id,
            ))

    def get_security_events(
        self,
        event_action: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list[SecurityEvent]:
        clauses, params = [], []
        if event_action:
            clauses.append("event_action = %s"); params.append(event_action)
        if source_ip:
            clauses.append("source_ip = %s"); params.append(source_ip)
        if tenant_id is not None:
            clauses.append("tenant_id = %s"); params.append(tenant_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM security_events {where} ORDER BY occurred_at DESC LIMIT %s",
                params,
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def count_security_events(self, event_action: Optional[str] = None) -> int:
        with self._connect() as conn:
            if event_action:
                row = conn.execute(
                    "SELECT COUNT(*) FROM security_events WHERE event_action = %s",
                    (event_action,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()
        return list(row.values())[0] if row else 0

    def count_recent_failures(self, source_ip: str, since_iso: str) -> int:
        since = _dt(since_iso)
        with self._connect() as conn:
            row = conn.execute(
                """SELECT COUNT(*) AS cnt FROM security_events
                   WHERE source_ip = %s AND event_action = %s AND occurred_at >= %s""",
                (source_ip, SecurityEventType.SSH_FAILURE.value, since),
            ).fetchone()
        return row["cnt"] if row else 0

    def _row_to_event(self, row: dict) -> SecurityEvent:
        return SecurityEvent(
            event_id    = row["event_id"],
            agent_id    = row["agent_id"],
            hostname    = row["hostname"],
            event_action= SecurityEventType(row["event_action"]),
            severity    = row["severity"],
            source_ip   = row["source_ip"],
            username    = row["username"],
            message     = row["message"],
            raw_data    = row["raw_data"],
            occurred_at = _dt(row["occurred_at"]),
            created_at  = _dt(row["created_at"]),
        )

    # ------------------------------------------------------------------ #
    #  RAW LOGS
    # ------------------------------------------------------------------ #

    def save_raw_log(self, raw: RawLog) -> None:
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO raw_logs
                    (raw_id, source_type, observer_hostname, received_at,
                     raw_content, parse_status, normalized_log_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (raw_id) DO NOTHING
            """, (
                raw.raw_id,
                raw.source_type.value if raw.source_type else None,
                raw.observer_hostname,
                raw.received_at,
                raw.raw_content,
                raw.parse_status.value,
                raw.normalized_log_id,
            ))

    def mark_raw_normalized(self, raw_id: str, normalized_log_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE raw_logs SET parse_status=%s, normalized_log_id=%s WHERE raw_id=%s",
                (ParseStatus.SUCCESS.value, normalized_log_id, raw_id),
            )

    def mark_raw_parse_failed(self, raw_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE raw_logs SET parse_status=%s WHERE raw_id=%s",
                (ParseStatus.FAILED.value, raw_id),
            )

    def get_unnormalized_raw_logs(self, limit: int = 100) -> list[RawLog]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM raw_logs WHERE parse_status=%s ORDER BY received_at ASC LIMIT %s",
                (ParseStatus.PENDING.value, limit),
            ).fetchall()
        return [self._row_to_raw_log(r) for r in rows]

    def _row_to_raw_log(self, row: dict) -> RawLog:
        return RawLog(
            raw_id            = row["raw_id"],
            source_type       = LogSourceType(row["source_type"]) if row.get("source_type") else None,
            observer_hostname  = row["observer_hostname"],
            received_at       = _dt(row["received_at"]),
            raw_content       = row["raw_content"],
            parse_status      = ParseStatus(row["parse_status"]) if row.get("parse_status") else ParseStatus.PENDING,
            normalized_log_id = row.get("normalized_log_id"),
        )

    # ------------------------------------------------------------------ #
    #  NORMALIZED LOGS
    # ------------------------------------------------------------------ #

    def save_normalized_log(self, log: NormalizedLog, tenant_id: str = "default") -> None:
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO normalized_logs
                    (log_id, raw_id, source_type, observer_hostname, timestamp,
                     received_at, severity, event_category, event_action,
                     source_ip, destination_ip, source_hostname, destination_hostname,
                     source_port, destination_port, network_protocol,
                     username, message, tags, extra, network_bytes, processed_at, tenant_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (log_id, received_at) DO NOTHING
            """, (
                log.log_id,
                log.raw_id,
                log.source_type.value,
                log.observer_hostname,
                log.timestamp,
                log.received_at,
                log.severity,
                log.event_category.value,
                log.event_action,
                log.source_ip,
                log.destination_ip,
                log.source_hostname,
                log.destination_hostname,
                log.source_port,
                log.destination_port,
                log.network_protocol,
                log.username,
                log.message,
                json.dumps(log.tags),
                json.dumps(log.extra),
                log.network_bytes,
                log.processed_at,
                tenant_id,
            ))

    def update_log_hostnames(
        self,
        log_id: str,
        src_host: Optional[str],
        dst_host: Optional[str],
    ) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE normalized_logs SET source_hostname=%s, destination_hostname=%s WHERE log_id=%s",
                (src_host, dst_host, log_id),
            )
            if cur.rowcount == 0:
                logger.debug("update_log_hostnames: log_id bulunamadı: %s", log_id)
                return False
            return True

    def get_normalized_logs(
        self,
        source_type: Optional[str] = None,
        event_category: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        network_protocol: Optional[str] = None,
        event_action: Optional[str] = None,
        severity: Optional[str] = None,
        since=None,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list[NormalizedLog]:
        clauses, params = [], []
        if source_type:
            clauses.append("source_type = %s"); params.append(source_type)
        if event_category:
            clauses.append("event_category = %s"); params.append(event_category)
        if source_ip:
            clauses.append("source_ip = %s"); params.append(source_ip)
        if destination_ip:
            clauses.append("destination_ip = %s"); params.append(destination_ip)
        if network_protocol:
            clauses.append("network_protocol = %s"); params.append(network_protocol)
        if event_action:
            clauses.append("event_action = %s"); params.append(event_action)
        if severity:
            clauses.append("severity = %s"); params.append(severity)
        if since is not None:
            clauses.append("timestamp >= %s"); params.append(since)
        if tenant_id is not None:
            clauses.append("tenant_id = %s"); params.append(tenant_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM normalized_logs {where} ORDER BY timestamp DESC LIMIT %s",
                params,
            ).fetchall()
        return [self._row_to_normalized_log(r) for r in rows]

    def get_normalized_logs_in_window(
        self,
        event_action_prefix: str,
        group_by: str,
        group_value: str,
        since_iso: str,
        severity: Optional[str] = None,
    ) -> list[NormalizedLog]:
        group_col = "source_ip" if group_by == "source_ip" else "observer_hostname"
        since = _dt(since_iso)
        params: list = [f"{event_action_prefix}%", group_value, since]
        severity_clause = ""
        if severity:
            severity_clause = "AND severity = %s"
            params.append(severity)
        with self._connect() as conn:
            rows = conn.execute(
                f"""SELECT * FROM normalized_logs
                    WHERE event_action LIKE %s
                      AND {group_col} = %s
                      AND timestamp >= %s
                      {severity_clause}
                    ORDER BY timestamp ASC""",
                params,
            ).fetchall()
        return [self._row_to_normalized_log(r) for r in rows]

    def get_log_volume(self, range: str = "24h", tenant_id: Optional[str] = None) -> list[dict]:
        hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}.get(range, 24)
        since = _now() - timedelta(hours=hours)
        params: list = [since]
        tenant_clause = ""
        if tenant_id is not None:
            tenant_clause = "AND tenant_id = %s"
            params.append(tenant_id)
        with self._connect() as conn:
            rows = conn.execute(
                f"""SELECT to_char(date_trunc('hour', received_at), 'YYYY-MM-DD"T"HH24:00:00"Z"') AS t,
                           COUNT(*) AS c
                    FROM normalized_logs
                    WHERE received_at >= %s {tenant_clause}
                    GROUP BY t ORDER BY t""",
                params,
            ).fetchall()
        return [{"t": r["t"], "c": r["c"]} for r in rows]

    def search_logs(
        self,
        query: str,
        source_type: Optional[str] = None,
        event_category: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list:
        q = query.strip()
        if not q:
            return self.get_normalized_logs(
                source_type=source_type, event_category=event_category, limit=limit, tenant_id=tenant_id
            )
        clauses: list[str] = []
        params: list = []
        if _IP_RE.match(q):
            clauses.append("(source_ip LIKE %s OR destination_ip LIKE %s OR observer_hostname LIKE %s)")
            pattern = f"{q}%"
            params.extend([pattern, pattern, pattern])
        else:
            clauses.append("""
                to_tsvector('simple',
                    COALESCE(message,'') || ' ' || COALESCE(source_ip,'') || ' ' ||
                    COALESCE(destination_ip,'') || ' ' || COALESCE(observer_hostname,'') || ' ' ||
                    COALESCE(username,'') || ' ' || COALESCE(event_action,'')
                ) @@ plainto_tsquery('simple', %s)
            """)
            params.append(q)
        if source_type:
            clauses.append("source_type = %s"); params.append(source_type)
        if event_category:
            clauses.append("event_category = %s"); params.append(event_category)
        if severity:
            clauses.append("severity = %s"); params.append(severity)
        if tenant_id is not None:
            clauses.append("tenant_id = %s"); params.append(tenant_id)
        where = "WHERE " + " AND ".join(clauses)
        params.append(limit)
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    f"SELECT * FROM normalized_logs {where} ORDER BY timestamp DESC LIMIT %s",
                    params,
                ).fetchall()
            return [self._row_to_normalized_log(r) for r in rows]
        except Exception as exc:
            logger.warning("search_logs başarısız [query=%r]: %s", q, exc)
            return []

    def get_log_aggregates_by_ip(
        self,
        since: datetime,
        tenant_id: str,
        min_events: int = 1,
    ) -> list[dict]:
        """source_ip başına olay istatistikleri — asset_baseline için."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT source_ip,
                       COUNT(*) AS total_events,
                       COUNT(DISTINCT date_trunc('hour', timestamp)) AS distinct_hours,
                       MIN(timestamp) AS first_seen,
                       MAX(timestamp) AS last_seen
                FROM normalized_logs
                WHERE source_ip IS NOT NULL
                  AND timestamp >= %s
                  AND tenant_id = %s
                GROUP BY source_ip
                HAVING COUNT(*) >= %s
                """,
                (since, tenant_id, min_events),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_top_values_by_ip(
        self,
        source_ip: str,
        column: str,
        since: datetime,
        tenant_id: str,
        limit: int = 5,
    ) -> list[dict]:
        """Bir kolondaki en sık N değer — asset_baseline _top_values için."""
        if column not in _VALID_TOP_VALUE_COLS:
            raise ValueError(f"get_top_values_by_ip: geçersiz column '{column}'")
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {column} AS val, COUNT(*) AS cnt
                FROM normalized_logs
                WHERE source_ip = %s
                  AND {column} IS NOT NULL
                  AND timestamp >= %s
                  AND tenant_id = %s
                GROUP BY {column}
                ORDER BY cnt DESC
                LIMIT %s
                """,
                (source_ip, since, tenant_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_event_counts_by_ip(self, since: datetime, tenant_id: str) -> list[dict]:
        """source_ip başına olay sayısı — asset_baseline sapma tespiti için."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT source_ip, COUNT(*) AS event_count
                FROM normalized_logs
                WHERE source_ip IS NOT NULL
                  AND timestamp >= %s
                  AND tenant_id = %s
                GROUP BY source_ip
                """,
                (since, tenant_id),
            ).fetchall()
        return [dict(r) for r in rows]

    def query_correlated_log_groups(
        self,
        event_action_prefix: str,
        since: datetime,
        group_col: str,
        count_expr: str,
        threshold: int,
        match_severity: Optional[str],
        keywords: list[str],
    ) -> list[dict]:
        """Korelasyon motoru GROUP BY sorgusu — correlator._apply_rule için."""
        if group_col not in _VALID_GROUP_COLS:
            raise ValueError(f"query_correlated_log_groups: geçersiz group_col '{group_col}'")
        if count_expr not in _VALID_COUNT_EXPRS:
            raise ValueError(f"query_correlated_log_groups: geçersiz count_expr '{count_expr}'")
        kw_clause = ""
        kw_params: list = []
        if keywords:
            parts = " OR ".join("message LIKE %s" for _ in keywords)
            kw_clause = f"AND ({parts})"
            kw_params = [f"%{kw}%" for kw in keywords]

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {group_col} AS grp_val,
                       {count_expr} AS cnt,
                       MIN(timestamp) AS first_ts, MAX(timestamp) AS last_ts
                FROM normalized_logs
                WHERE event_action LIKE %s
                  AND timestamp >= %s
                  {"AND severity = %s" if match_severity else ""}
                  AND {group_col} IS NOT NULL
                  {kw_clause}
                GROUP BY {group_col}
                HAVING {count_expr} >= %s
                """,
                (
                    f"{event_action_prefix}%",
                    since,
                    *([match_severity] if match_severity else []),
                    *kw_params,
                    threshold,
                ),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_network_intelligence(self, since: str, tenant_id: str) -> dict:
        """Zeek/TLS/SSL/FTP/SMTP/DNS istatistiklerini tek sorguda toplar — network_intel route için."""
        _HOUR_EXPR = "to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD\"T\"HH24:00:00\"Z\"')"
        params_ts = [since, tenant_id]
        with self._connect() as conn:
            zeek_dist: dict = {}
            for r in conn.execute(
                "SELECT event_action, COUNT(*) AS cnt FROM normalized_logs"
                " WHERE source_type = 'zeek' AND timestamp >= %s AND tenant_id = %s"
                " GROUP BY event_action ORDER BY cnt DESC LIMIT 20",
                params_ts,
            ).fetchall():
                zeek_dist[r["event_action"]] = r["cnt"]

            ja3_rows = conn.execute(
                "SELECT source_ip, destination_ip, message, timestamp FROM normalized_logs"
                " WHERE event_action = 'tls_suspicious_fingerprint'"
                "   AND timestamp >= %s AND tenant_id = %s ORDER BY timestamp DESC LIMIT 50",
                params_ts,
            ).fetchall()

            ssl_rows = conn.execute(
                "SELECT source_ip, destination_ip, message, severity, timestamp FROM normalized_logs"
                " WHERE event_action = 'ssl_connection' AND severity = 'warning'"
                "   AND timestamp >= %s AND tenant_id = %s ORDER BY timestamp DESC LIMIT 50",
                params_ts,
            ).fetchall()

            x509_rows = conn.execute(
                "SELECT source_ip, message, timestamp FROM normalized_logs"
                " WHERE event_action = 'x509_certificate' AND severity = 'warning'"
                "   AND timestamp >= %s AND tenant_id = %s ORDER BY timestamp DESC LIMIT 30",
                params_ts,
            ).fetchall()

            ftp_rows = conn.execute(
                "SELECT source_ip, destination_ip, message, timestamp FROM normalized_logs"
                " WHERE event_action = 'ftp_command' AND severity = 'warning'"
                "   AND timestamp >= %s AND tenant_id = %s ORDER BY timestamp DESC LIMIT 30",
                params_ts,
            ).fetchall()

            smtp_rows = conn.execute(
                "SELECT source_ip, destination_ip, message, timestamp FROM normalized_logs"
                " WHERE event_action = 'smtp_session'"
                "   AND timestamp >= %s AND tenant_id = %s ORDER BY timestamp DESC LIMIT 30",
                params_ts,
            ).fetchall()

            top_src_rows = conn.execute(
                "SELECT source_ip, COUNT(*) AS cnt FROM normalized_logs"
                " WHERE source_type = 'zeek' AND source_ip IS NOT NULL"
                "   AND timestamp >= %s AND tenant_id = %s"
                " GROUP BY source_ip ORDER BY cnt DESC LIMIT 10",
                params_ts,
            ).fetchall()

            dns_rows = conn.execute(
                "SELECT message, COUNT(*) AS cnt FROM normalized_logs"
                " WHERE event_action = 'dns_query'"
                "   AND timestamp >= %s AND tenant_id = %s"
                " GROUP BY message ORDER BY cnt DESC LIMIT 10",
                params_ts,
            ).fetchall()

            timeline_rows = conn.execute(
                f"SELECT {_HOUR_EXPR} AS hour, COUNT(*) AS cnt FROM normalized_logs"
                " WHERE source_type = 'zeek' AND timestamp >= %s AND tenant_id = %s"
                " GROUP BY hour ORDER BY hour ASC",
                params_ts,
            ).fetchall()

        return {
            "zeek_distribution": zeek_dist,
            "ja3_rows":          [dict(r) for r in ja3_rows],
            "ssl_rows":          [dict(r) for r in ssl_rows],
            "x509_rows":         [dict(r) for r in x509_rows],
            "ftp_rows":          [dict(r) for r in ftp_rows],
            "smtp_rows":         [dict(r) for r in smtp_rows],
            "top_src_rows":      [dict(r) for r in top_src_rows],
            "dns_rows":          [dict(r) for r in dns_rows],
            "timeline_rows":     [dict(r) for r in timeline_rows],
        }

    def _row_to_normalized_log(self, row: dict) -> NormalizedLog:
        return NormalizedLog(
            log_id               = row["log_id"],
            raw_id               = row.get("raw_id"),
            source_type          = LogSourceType(row["source_type"]),
            observer_hostname    = row["observer_hostname"],
            timestamp            = _dt(row["timestamp"]),
            received_at          = _dt(row["received_at"]),
            severity             = row["severity"],
            event_category       = LogCategory(row["event_category"]),
            event_action         = row["event_action"],
            source_ip            = row.get("source_ip"),
            destination_ip       = row.get("destination_ip"),
            source_hostname      = row.get("source_hostname"),
            destination_hostname = row.get("destination_hostname"),
            source_port          = row.get("source_port"),
            destination_port     = row.get("destination_port"),
            network_protocol     = row.get("network_protocol"),
            username             = row.get("username"),
            message              = row["message"],
            tags                 = json.loads(row.get("tags") or "[]"),
            processed_at         = _dt(row["processed_at"]),
        )

    def get_related_logs_for_incident(
        self,
        source_ip: str,
        around_iso: str,
        window_minutes: int = 30,
        limit: int = 20,
        group_by_field: str = "source_ip",
    ) -> list[NormalizedLog]:
        if group_by_field not in self._VALID_LOG_GROUP_FIELDS:
            logger.warning("Geçersiz group_by_field: %r → source_ip kullanılıyor", group_by_field)
            group_by_field = "source_ip"
        around_dt = _dt(around_iso)
        before = around_dt - timedelta(minutes=window_minutes)
        after  = around_dt + timedelta(minutes=window_minutes)
        with self._connect() as conn:
            rows = conn.execute(
                f"""SELECT * FROM normalized_logs
                    WHERE {group_by_field} = %s
                      AND timestamp BETWEEN %s AND %s
                    ORDER BY timestamp DESC LIMIT %s""",
                (source_ip, before, after, limit),
            ).fetchall()
        return [self._row_to_normalized_log(r) for r in rows]

    # ------------------------------------------------------------------ #
    #  CORRELATED EVENTS
    # ------------------------------------------------------------------ #

    def save_correlated_event(self, event: CorrelatedEvent) -> bool:
        since = _now() - timedelta(seconds=event.window_seconds)
        with self._connect() as conn:
            existing = conn.execute(
                """SELECT corr_id FROM correlated_events
                   WHERE rule_id=%s AND group_value=%s AND created_at >= %s LIMIT 1""",
                (event.rule_id, event.group_value, since),
            ).fetchone()
            if existing:
                return False
            conn.execute("""
                INSERT INTO correlated_events
                    (corr_id, rule_id, rule_name, event_action, severity,
                     group_value, matched_count, window_seconds,
                     first_seen, last_seen, message, created_at,
                     mitre_techniques, mitre_tactics)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (
                event.corr_id,
                event.rule_id,
                event.rule_name,
                event.event_action,
                event.severity,
                event.group_value,
                event.matched_count,
                event.window_seconds,
                event.first_seen,
                event.last_seen,
                event.message,
                event.created_at,
                ",".join(event.mitre_techniques),
                ",".join(event.mitre_tactics),
            ))
            return True

    def get_correlated_events(
        self,
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list[CorrelatedEvent]:
        clauses, params = [], []
        if rule_id:
            clauses.append("rule_id = %s"); params.append(rule_id)
        if severity:
            clauses.append("severity = %s"); params.append(severity)
        if tenant_id is not None:
            clauses.append("tenant_id = %s"); params.append(tenant_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM correlated_events {where} ORDER BY created_at DESC LIMIT %s",
                params,
            ).fetchall()
        return [self._row_to_correlated_event(r) for r in rows]

    def get_correlated_event_by_id(self, corr_id: str, tenant_id: Optional[str] = None) -> Optional[CorrelatedEvent]:
        params: list = [corr_id]
        extra = " AND tenant_id=%s" if tenant_id is not None else ""
        if tenant_id is not None:
            params.append(tenant_id)
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM correlated_events WHERE corr_id=%s{extra}", params
            ).fetchone()
        return self._row_to_correlated_event(row) if row else None

    def _row_to_correlated_event(self, row: dict) -> CorrelatedEvent:
        def _split(val: str) -> list[str]:
            return [v for v in (val or "").split(",") if v]
        return CorrelatedEvent(
            corr_id          = row["corr_id"],
            rule_id          = row["rule_id"],
            rule_name        = row["rule_name"],
            event_action     = row["event_action"],
            severity         = row["severity"],
            group_value      = row["group_value"],
            matched_count    = row["matched_count"],
            window_seconds   = row["window_seconds"],
            first_seen       = _dt(row["first_seen"]),
            last_seen        = _dt(row["last_seen"]),
            message          = row["message"],
            created_at       = _dt(row["created_at"]),
            mitre_techniques = _split(row.get("mitre_techniques", "")),
            mitre_tactics    = _split(row.get("mitre_tactics", "")),
        )

    def count_correlated_events_since(self, hours: int = 24, tenant_id: Optional[str] = None) -> dict:
        since = _now() - timedelta(hours=hours)
        clauses = ["created_at >= %s"]
        params: list = [since]
        if tenant_id is not None:
            clauses.append("tenant_id = %s"); params.append(tenant_id)
        where = "WHERE " + " AND ".join(clauses)
        with self._connect() as conn:
            row = conn.execute(
                f"""SELECT COUNT(*) AS total,
                    SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) AS high_plus
                    FROM correlated_events {where}""",
                params,
            ).fetchone()
        return {"total": row["total"] or 0, "high_plus": row["high_plus"] or 0}

    def get_rule_alert_counts(self, since: datetime) -> list[dict]:
        """rule_id başına correlated_events sayısı — MITRE activity/heatmap için."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT rule_id, COUNT(*) AS cnt FROM correlated_events WHERE created_at >= %s GROUP BY rule_id",
                (since,),
            ).fetchall()
        return [{"rule_id": r["rule_id"], "cnt": r["cnt"]} for r in rows]

    def get_rule_hit_stats(self, since: datetime) -> dict[str, dict]:
        """rule_id → {count, last_hit} — kural kalite analizi için."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT rule_id, COUNT(*) AS cnt, MAX(created_at) AS last_hit
                   FROM correlated_events WHERE created_at >= %s
                   GROUP BY rule_id""",
                (since,),
            ).fetchall()
        return {
            r["rule_id"]: {
                "count": r["cnt"],
                "last_hit": r["last_hit"].isoformat() if r["last_hit"] else None,
            }
            for r in rows
        }

    # ------------------------------------------------------------------ #
    #  KEV ENTRIES (N7 CISA Known Exploited Vulnerabilities)
    # ------------------------------------------------------------------ #

    def upsert_kev_entries(self, entries: list[dict]) -> list[str]:
        """Yeni CVE'leri ekler, mevcutları atlar. Eklenen cve_id listesi döner."""
        if not entries:
            return []
        new_ids: list[str] = []
        with self._connect() as conn:
            for e in entries:
                existing = conn.execute(
                    "SELECT 1 FROM kev_entries WHERE cve_id = %s", (e["cve_id"],)
                ).fetchone()
                if existing:
                    continue
                conn.execute(
                    """INSERT INTO kev_entries
                       (cve_id, vendor_project, product, vulnerability_name,
                        date_added, due_date, description, required_action, seen_at)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW())""",
                    (
                        e["cve_id"],
                        e.get("vendor_project", ""),
                        e.get("product", ""),
                        e.get("vulnerability_name", ""),
                        e.get("date_added"),
                        e.get("due_date"),
                        e.get("description", ""),
                        e.get("required_action", ""),
                    ),
                )
                new_ids.append(e["cve_id"])
        return new_ids

    def get_kev_entries(self, limit: int = 50, vendor: str = "") -> list[dict]:
        """KEV girdilerini döndür — isteğe bağlı vendor filtresi."""
        with self._connect() as conn:
            if vendor:
                rows = conn.execute(
                    """SELECT * FROM kev_entries
                       WHERE LOWER(vendor_project) LIKE %s
                       ORDER BY date_added DESC LIMIT %s""",
                    (f"%{vendor.lower()}%", limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM kev_entries ORDER BY date_added DESC LIMIT %s",
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_kev_stats(self) -> dict:
        """KEV özet istatistikleri."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS cnt FROM kev_entries").fetchone()["cnt"]
            last_added = conn.execute(
                "SELECT MAX(date_added) AS d FROM kev_entries"
            ).fetchone()["d"]
            last_seen = conn.execute(
                "SELECT MAX(seen_at) AS d FROM kev_entries"
            ).fetchone()["d"]
        return {
            "total_cves": total,
            "last_cve_date": str(last_added) if last_added else None,
            "last_fetch_at": last_seen.isoformat() if last_seen else None,
        }

    # ------------------------------------------------------------------ #
    #  ALERT EXPLANATIONS (F4 AI Explainer cache)
    # ------------------------------------------------------------------ #

    def get_alert_explanation(self, corr_id: str, tenant_id: str, ttl_hours: int = 24) -> Optional[dict]:
        """Cache hit döner, 24 saat TTL aşıldıysa None."""
        since = _now() - timedelta(hours=ttl_hours)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM alert_explanations WHERE corr_id=%s AND tenant_id=%s AND created_at>=%s",
                (corr_id, tenant_id, since),
            ).fetchone()
        if row is None:
            return None
        return {
            "explanation":    row["explanation"],
            "model":          row["model"],
            "input_tokens":   row["input_tokens"],
            "output_tokens":  row["output_tokens"],
            "created_at":     row["created_at"].isoformat(),
            "cached":         True,
        }

    def save_alert_explanation(
        self,
        corr_id: str,
        tenant_id: str,
        explanation: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO alert_explanations
                       (corr_id, tenant_id, explanation, model, input_tokens, output_tokens)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   ON CONFLICT (corr_id, tenant_id)
                   DO UPDATE SET explanation=%s, model=%s, input_tokens=%s, output_tokens=%s, created_at=NOW()""",
                (corr_id, tenant_id, explanation, model, input_tokens, output_tokens,
                 explanation, model, input_tokens, output_tokens),
            )

    # ------------------------------------------------------------------ #
    #  SAVED HUNTS (F5 Threat Hunt Workbench)
    # ------------------------------------------------------------------ #

    def create_hunt(
        self,
        hunt_id: str,
        tenant_id: str,
        created_by: str,
        name: str,
        description: str,
        filter_params: str,
        tags: str = "[]",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO saved_hunts
                       (hunt_id, tenant_id, created_by, name, description, filter_params, tags)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (hunt_id, tenant_id, created_by, name, description, filter_params, tags),
            )

    def get_hunts(self, tenant_id: str, created_by: Optional[str] = None) -> list[dict]:
        clauses = ["tenant_id = %s"]
        params: list = [tenant_id]
        if created_by is not None:
            clauses.append("created_by = %s")
            params.append(created_by)
        where = "WHERE " + " AND ".join(clauses)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM saved_hunts {where} ORDER BY is_favorite DESC, updated_at DESC",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    def get_hunt(self, hunt_id: str, tenant_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM saved_hunts WHERE hunt_id=%s AND tenant_id=%s",
                (hunt_id, tenant_id),
            ).fetchone()
        return dict(row) if row else None

    def update_hunt(
        self,
        hunt_id: str,
        tenant_id: str,
        name: str,
        description: str,
        filter_params: str,
        tags: str,
        is_favorite: bool,
    ) -> bool:
        with self._connect() as conn:
            result = conn.execute(
                """UPDATE saved_hunts
                   SET name=%s, description=%s, filter_params=%s,
                       tags=%s, is_favorite=%s, updated_at=NOW()
                   WHERE hunt_id=%s AND tenant_id=%s""",
                (name, description, filter_params, tags, is_favorite, hunt_id, tenant_id),
            )
        return result.rowcount > 0

    def delete_hunt(self, hunt_id: str, tenant_id: str) -> bool:
        with self._connect() as conn:
            result = conn.execute(
                "DELETE FROM saved_hunts WHERE hunt_id=%s AND tenant_id=%s",
                (hunt_id, tenant_id),
            )
        return result.rowcount > 0

    def record_hunt_run(self, hunt_id: str, tenant_id: str, result_count: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """UPDATE saved_hunts
                   SET run_count = run_count + 1,
                       last_run_at = NOW(),
                       last_run_count = %s
                   WHERE hunt_id=%s AND tenant_id=%s""",
                (result_count, hunt_id, tenant_id),
            )

    # ------------------------------------------------------------------ #
    #  ATTACK CHAIN STATE
    # ------------------------------------------------------------------ #

    def save_chain_stage(self, source_ip: str, stage: str, occurred_at: datetime, tenant_id: str = "default") -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO attack_chain_state (source_ip, stage, occurred_at, tenant_id) VALUES (%s,%s,%s,%s)",
                (source_ip, stage, occurred_at, tenant_id),
            )

    def get_active_chain_stages(self, window_seconds: int = 1800) -> dict:
        from collections import defaultdict
        since = _now() - timedelta(seconds=window_seconds)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT source_ip, stage, occurred_at FROM attack_chain_state WHERE occurred_at >= %s ORDER BY occurred_at",
                (since,),
            ).fetchall()
        result: dict = defaultdict(lambda: defaultdict(list))
        for row in rows:
            result[row["source_ip"]][row["stage"]].append(_dt(row["occurred_at"]))
        return result

    def purge_old_chain_stages(self, window_seconds: int = 1800) -> None:
        cutoff = _now() - timedelta(seconds=window_seconds)
        with self._connect() as conn:
            conn.execute("DELETE FROM attack_chain_state WHERE occurred_at < %s", (cutoff,))

    # ------------------------------------------------------------------ #
    #  ASSET BASELINES
    # ------------------------------------------------------------------ #

    def upsert_asset_baseline(
        self,
        source_ip: str,
        tenant_id: str,
        first_seen_at: str,
        last_seen_at: str,
        avg_events_per_hour: float,
        typical_ports: list,
        typical_destinations: list,
        typical_event_actions: list,
        sample_hours: int,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO asset_baselines
                   (source_ip, tenant_id, first_seen_at, last_seen_at,
                    avg_events_per_hour, typical_ports, typical_destinations,
                    typical_event_actions, sample_hours, updated_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (source_ip, tenant_id) DO UPDATE SET
                       last_seen_at          = EXCLUDED.last_seen_at,
                       avg_events_per_hour   = EXCLUDED.avg_events_per_hour,
                       typical_ports         = EXCLUDED.typical_ports,
                       typical_destinations  = EXCLUDED.typical_destinations,
                       typical_event_actions = EXCLUDED.typical_event_actions,
                       sample_hours          = EXCLUDED.sample_hours,
                       updated_at            = EXCLUDED.updated_at""",
                (
                    source_ip, tenant_id, _dt(first_seen_at), _dt(last_seen_at),
                    avg_events_per_hour,
                    json.dumps(typical_ports),
                    json.dumps(typical_destinations),
                    json.dumps(typical_event_actions),
                    sample_hours, _now(),
                ),
            )

    def get_all_asset_baselines(self, tenant_id: str = "default") -> dict[str, dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM asset_baselines WHERE tenant_id = %s", (tenant_id,)
            ).fetchall()
        result = {}
        for r in rows:
            result[r["source_ip"]] = {
                "source_ip":             r["source_ip"],
                "tenant_id":             r["tenant_id"],
                "first_seen_at":         r["first_seen_at"].isoformat() if r["first_seen_at"] else None,
                "last_seen_at":          r["last_seen_at"].isoformat() if r["last_seen_at"] else None,
                "avg_events_per_hour":   r["avg_events_per_hour"],
                "typical_ports":         json.loads(r["typical_ports"] or "[]"),
                "typical_destinations":  json.loads(r["typical_destinations"] or "[]"),
                "typical_event_actions": json.loads(r["typical_event_actions"] or "[]"),
                "sample_hours":          r["sample_hours"],
                "updated_at":            r["updated_at"].isoformat() if r["updated_at"] else None,
            }
        return result

    def get_asset_baseline(self, source_ip: str, tenant_id: str = "default") -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM asset_baselines WHERE source_ip=%s AND tenant_id=%s",
                (source_ip, tenant_id),
            ).fetchone()
        if not row:
            return None
        return {
            "source_ip":             row["source_ip"],
            "tenant_id":             row["tenant_id"],
            "first_seen_at":         row["first_seen_at"].isoformat() if row["first_seen_at"] else None,
            "last_seen_at":          row["last_seen_at"].isoformat() if row["last_seen_at"] else None,
            "avg_events_per_hour":   row["avg_events_per_hour"],
            "typical_ports":         json.loads(row["typical_ports"] or "[]"),
            "typical_destinations":  json.loads(row["typical_destinations"] or "[]"),
            "typical_event_actions": json.loads(row["typical_event_actions"] or "[]"),
            "sample_hours":          row["sample_hours"],
            "updated_at":            row["updated_at"].isoformat() if row["updated_at"] else None,
        }

    # ── False Positive Rules ──────────────────────────────────────────

    def create_fp_rule(
        self,
        fp_rule_id: str,
        event_action: Optional[str],
        source_ip: Optional[str],
        destination_ip: Optional[str],
        destination_port: Optional[str],
        observer_hostname: Optional[str],
        tenant_id: str,
        reason: str,
        created_by: str,
        created_at: str,
        expires_at: Optional[str],
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO fp_rules
                   (fp_rule_id, event_action, source_ip, destination_ip,
                    destination_port, observer_hostname, tenant_id, reason, created_by,
                    created_at, expires_at, is_active, hit_count)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,0)""",
                (fp_rule_id, event_action, source_ip, destination_ip,
                 destination_port, observer_hostname, tenant_id, reason,
                 created_by, _dt(created_at), _dt(expires_at) if expires_at else None),
            )

    def get_active_fp_rules(self, tenant_id: str = "default") -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM fp_rules WHERE tenant_id=%s AND is_active=1 ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
        return [_fp_row_to_dict(r) for r in rows]

    def get_all_fp_rules(self, tenant_id: str = "default") -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM fp_rules WHERE tenant_id=%s ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
        return [_fp_row_to_dict(r) for r in rows]

    def deactivate_fp_rule(self, fp_rule_id: str, tenant_id: str = "default") -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE fp_rules SET is_active=0 WHERE fp_rule_id=%s AND tenant_id=%s",
                (fp_rule_id, tenant_id),
            )
            return cur.rowcount > 0

    def increment_fp_hit(self, fp_rule_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE fp_rules SET hit_count=hit_count+1 WHERE fp_rule_id=%s",
                (fp_rule_id,),
            )

    # ── Blocked IPs ───────────────────────────────────────────────────────

    def block_ip(
        self,
        block_id: str,
        ip: str,
        reason: str,
        blocked_by: str,
        source_incident_id: Optional[str] = None,
        provider: str = "opnsense",
        tenant_id: str = "default",
        ttl_hours: Optional[float] = None,
        offense_count: int = 1,
    ) -> None:
        expires_at = None
        if ttl_hours is not None:
            expires_at = _now() + timedelta(hours=ttl_hours)
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO blocked_ips
                   (block_id, ip, reason, blocked_by, blocked_at,
                    is_active, source_incident_id, provider, tenant_id, expires_at, offense_count)
                   VALUES (%s, %s, %s, %s, %s, 1, %s, %s, %s, %s, %s)
                   ON CONFLICT (block_id) DO NOTHING""",
                (block_id, ip, reason, blocked_by,
                 _now(),
                 source_incident_id, provider, tenant_id, expires_at, offense_count),
            )

    def unblock_ip(self, ip: str, unblocked_by: str, tenant_id: str = "default") -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                """UPDATE blocked_ips
                   SET is_active=0, unblocked_at=%s, unblocked_by=%s
                   WHERE ip=%s AND is_active=1 AND tenant_id=%s""",
                (_now(), unblocked_by, ip, tenant_id),
            )
            return cur.rowcount > 0

    def get_blocked_ips(self, active_only: bool = True, tenant_id: Optional[str] = None) -> list[dict]:
        clauses = []
        params: list = []
        if active_only:
            clauses.append("is_active = 1")
        if tenant_id is not None:
            clauses.append("tenant_id = %s")
            params.append(tenant_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM blocked_ips {where} ORDER BY blocked_at DESC",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    def get_block_by_ip(self, ip: str, tenant_id: str = "default") -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM blocked_ips WHERE ip=%s AND is_active=1 AND tenant_id=%s LIMIT 1",
                (ip, tenant_id),
            ).fetchone()
        return dict(row) if row else None

    def is_ip_blocked(self, ip: str, tenant_id: str = "default") -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM blocked_ips WHERE ip=%s AND is_active=1 AND tenant_id=%s LIMIT 1",
                (ip, tenant_id),
            ).fetchone()
        return row is not None

    def get_offense_count(self, ip: str, tenant_id: str = "default") -> int:
        """IP'nin tüm zamanlar bloklanma sayısını döndür (aktif + pasif)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM blocked_ips WHERE ip=%s AND tenant_id=%s",
                (ip, tenant_id),
            ).fetchone()
        return int(row["cnt"]) if row else 0

    def get_expired_blocks(self, tenant_id: Optional[str] = None) -> list[dict]:
        now = _now()
        clauses = ["is_active = 1", "expires_at IS NOT NULL", "expires_at <= %s"]
        params: list = [now]
        if tenant_id is not None:
            clauses.append("tenant_id = %s")
            params.append(tenant_id)
        where = f"WHERE {' AND '.join(clauses)}"
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM blocked_ips {where}", params
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    #  SNMP DEVICES
    # ------------------------------------------------------------------ #

    def add_snmp_device(self, host: str, community: str = "public", label: str = "") -> bool:
        with self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO snmp_devices (host, community, label, enabled, added_at) VALUES (%s,%s,%s,1,%s)",
                    (host, community, label, _now()),
                )
                return True
            except psycopg.errors.UniqueViolation:
                return False

    def get_snmp_devices(self, enabled_only: bool = True) -> list[dict]:
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

    def get_pollable_devices(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT ip AS host, snmp_community AS community, snmp_version,
                          snmp_v3_username, snmp_v3_auth_protocol, snmp_v3_auth_key,
                          snmp_v3_priv_protocol, snmp_v3_priv_key, name AS label
                   FROM devices
                   WHERE snmp_community != '' AND status != 'offline'
                   ORDER BY device_id"""
            ).fetchall()
            if rows:
                return [dict(r) for r in rows]
            rows = conn.execute(
                "SELECT host, community, 'v2c' AS snmp_version, label FROM snmp_devices WHERE enabled=1 ORDER BY added_at"
            ).fetchall()
        return [dict(r) for r in rows]

    def remove_snmp_device(self, host: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM snmp_devices WHERE host=%s", (host,))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    #  DEVICES
    # ------------------------------------------------------------------ #

    def save_device(
        self,
        device_id: str,
        name: str,
        device_type: str,
        ip: str = "",
        mac: str = "",
        vendor: str = "",
        os_info: str = "",
        snmp_community: str = "",
        snmp_version: str = "v2c",
        snmp_v3_username: str = "",
        snmp_v3_auth_protocol: str = "SHA",
        snmp_v3_auth_key: str = "",
        snmp_v3_priv_protocol: str = "AES",
        snmp_v3_priv_key: str = "",
        status: str = "unknown",
        segment: str = "",
        notes: str = "",
        tenant_id: str = "default",
    ) -> None:
        now = _now()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO devices
                       (device_id, name, ip, mac, type, vendor, os_info,
                        status, first_seen, last_seen,
                        snmp_community, snmp_version,
                        snmp_v3_username, snmp_v3_auth_protocol,
                        snmp_v3_auth_key, snmp_v3_priv_protocol, snmp_v3_priv_key,
                        segment, notes, tenant_id)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (device_id) DO UPDATE SET
                       name                  = EXCLUDED.name,
                       ip                    = COALESCE(NULLIF(EXCLUDED.ip,''), devices.ip),
                       status                = EXCLUDED.status,
                       last_seen             = EXCLUDED.last_seen,
                       os_info               = COALESCE(NULLIF(EXCLUDED.os_info,''), devices.os_info),
                       vendor                = COALESCE(NULLIF(EXCLUDED.vendor,''), devices.vendor),
                       snmp_community        = COALESCE(NULLIF(EXCLUDED.snmp_community,''), devices.snmp_community),
                       snmp_version          = COALESCE(NULLIF(EXCLUDED.snmp_version,''), devices.snmp_version),
                       snmp_v3_username      = COALESCE(NULLIF(EXCLUDED.snmp_v3_username,''), devices.snmp_v3_username),
                       snmp_v3_auth_protocol = COALESCE(NULLIF(EXCLUDED.snmp_v3_auth_protocol,''), devices.snmp_v3_auth_protocol),
                       snmp_v3_auth_key      = COALESCE(NULLIF(EXCLUDED.snmp_v3_auth_key,''), devices.snmp_v3_auth_key),
                       snmp_v3_priv_protocol = COALESCE(NULLIF(EXCLUDED.snmp_v3_priv_protocol,''), devices.snmp_v3_priv_protocol),
                       snmp_v3_priv_key      = COALESCE(NULLIF(EXCLUDED.snmp_v3_priv_key,''), devices.snmp_v3_priv_key)""",
                (device_id, name, ip, mac, device_type, vendor, os_info,
                 status, now, now,
                 snmp_community, snmp_version,
                 snmp_v3_username, snmp_v3_auth_protocol,
                 snmp_v3_auth_key, snmp_v3_priv_protocol, snmp_v3_priv_key,
                 segment, notes, tenant_id),
            )

    def update_device_status(self, device_id: str, status: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE devices SET status=%s, last_seen=%s WHERE device_id=%s",
                (status, _now(), device_id),
            )

    def get_devices(self, device_type: Optional[str] = None, tenant_id: Optional[str] = None) -> list[dict]:
        clauses, params = [], []
        if device_type:
            clauses.append("type=%s"); params.append(device_type)
        if tenant_id is not None:
            clauses.append("tenant_id=%s"); params.append(tenant_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(f"SELECT * FROM devices {where} ORDER BY type, name", params).fetchall()
        return [dict(r) for r in rows]

    def update_device_snmp(
        self,
        device_id: str,
        community: str,
        version: str,
        v3_username: str = "",
        v3_auth_protocol: str = "SHA",
        v3_auth_key: str = "",
        v3_priv_protocol: str = "AES",
        v3_priv_key: str = "",
    ) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                """UPDATE devices SET snmp_community=%s, snmp_version=%s,
                   snmp_v3_username=%s, snmp_v3_auth_protocol=%s,
                   snmp_v3_auth_key=%s, snmp_v3_priv_protocol=%s, snmp_v3_priv_key=%s
                   WHERE device_id=%s""",
                (community, version, v3_username, v3_auth_protocol,
                 v3_auth_key, v3_priv_protocol, v3_priv_key, device_id),
            )
            return cur.rowcount > 0

    def get_device(self, device_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM devices WHERE device_id=%s", (device_id,)).fetchone()
        return dict(row) if row else None

    def remove_device(self, device_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM devices WHERE device_id=%s", (device_id,))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    #  SNMP POLL HISTORY
    # ------------------------------------------------------------------ #

    def upsert_snmp_poll(self, host: str, if_index: str, if_name: str, hc_in: int, hc_out: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO snmp_poll_history (host, if_index, if_name, polled_at, hc_in, hc_out)
                   VALUES (%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (host, if_index) DO UPDATE SET
                       if_name=%s, polled_at=%s, hc_in=%s, hc_out=%s""",
                (host, if_index, if_name, _now(), hc_in, hc_out,
                 if_name, _now(), hc_in, hc_out),
            )

    def get_snmp_poll(self, host: str, if_index: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM snmp_poll_history WHERE host=%s AND if_index=%s",
                (host, if_index),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------ #
    #  SERVICE CHECKS
    # ------------------------------------------------------------------ #

    def save_service_check(
        self,
        device_id: str,
        check_type: str,
        target: str,
        status: str,
        rtt_ms: Optional[float] = None,
        port: Optional[int] = None,
        details: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO service_checks
                   (device_id, check_type, target, port, status, rtt_ms, checked_at, details)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (device_id, check_type, target, port, status, rtt_ms, _now(), details),
            )

    def get_service_checks(
        self,
        device_id: Optional[str] = None,
        check_type: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        conditions, params = [], []
        if device_id:
            conditions.append("device_id=%s"); params.append(device_id)
        if check_type:
            conditions.append("check_type=%s"); params.append(check_type)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM service_checks {where} ORDER BY checked_at DESC LIMIT %s",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    #  TENANTS
    # ------------------------------------------------------------------ #

    def ensure_default_tenant(self) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO tenants (id, name) VALUES (%s,%s) ON CONFLICT (id) DO NOTHING",
                ("default", "Default"),
            )

    def create_tenant(self, id: str, name: str) -> bool:
        with self._connect() as conn:
            try:
                conn.execute("INSERT INTO tenants (id, name) VALUES (%s,%s)", (id, name))
                return True
            except psycopg.errors.UniqueViolation:
                return False

    def get_tenants(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM tenants ORDER BY name").fetchall()
        return [dict(r) for r in rows]

    def get_tenant(self, id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tenants WHERE id=%s", (id,)).fetchone()
        return dict(row) if row else None

    def update_tenant(self, id: str, name: Optional[str] = None, is_active: Optional[int] = None) -> bool:
        fields, params = [], []
        if name is not None:
            fields.append("name=%s"); params.append(name)
        if is_active is not None:
            fields.append("is_active=%s"); params.append(is_active)
        if not fields:
            return False
        params.append(id)
        with self._connect() as conn:
            cur = conn.execute(f"UPDATE tenants SET {','.join(fields)} WHERE id=%s", params)
            return cur.rowcount > 0

    def delete_tenant(self, id: str) -> bool:
        if id == "default":
            return False
        with self._connect() as conn:
            if not conn.execute("SELECT 1 FROM tenants WHERE id=%s", (id,)).fetchone():
                return False
            conn.execute("DELETE FROM sites WHERE tenant_id=%s", (id,))
            conn.execute("DELETE FROM db_users WHERE tenant_id=%s", (id,))
            conn.execute("DELETE FROM tenants WHERE id=%s", (id,))
            return True

    # ------------------------------------------------------------------ #
    #  SITES
    # ------------------------------------------------------------------ #

    def create_site(self, id: str, tenant_id: str, name: str, location: str = "", tz: str = "UTC") -> bool:
        with self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO sites (id, tenant_id, name, location, tz) VALUES (%s,%s,%s,%s,%s)",
                    (id, tenant_id, name, location, tz),
                )
                return True
            except psycopg.errors.UniqueViolation:
                return False

    def get_sites(self, tenant_id: Optional[str] = None) -> list[dict]:
        with self._connect() as conn:
            if tenant_id:
                rows = conn.execute("SELECT * FROM sites WHERE tenant_id=%s ORDER BY name", (tenant_id,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM sites ORDER BY tenant_id, name").fetchall()
        return [dict(r) for r in rows]

    def get_site(self, id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM sites WHERE id=%s", (id,)).fetchone()
        return dict(row) if row else None

    def delete_site(self, id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM sites WHERE id=%s", (id,))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    #  DB USERS
    # ------------------------------------------------------------------ #

    def create_db_user(self, username: str, password_hash: str, role: str, tenant_id: Optional[str]) -> bool:
        with self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO db_users (username, password_hash, role, tenant_id) VALUES (%s,%s,%s,%s)",
                    (username, password_hash, role, tenant_id),
                )
                return True
            except psycopg.errors.UniqueViolation:
                return False

    def get_db_user(self, username: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM db_users WHERE username=%s", (username,)).fetchone()
        return dict(row) if row else None

    def get_db_users(self, tenant_id: Optional[str] = None) -> list[dict]:
        with self._connect() as conn:
            if tenant_id is not None:
                rows = conn.execute(
                    "SELECT username, role, tenant_id, created_at FROM db_users WHERE tenant_id=%s ORDER BY username",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT username, role, tenant_id, created_at FROM db_users ORDER BY tenant_id, username"
                ).fetchall()
        return [dict(r) for r in rows]

    def delete_db_user(self, username: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM db_users WHERE username=%s", (username,))
            return cur.rowcount > 0

    def update_db_user_password(self, username: str, password_hash: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("UPDATE db_users SET password_hash=%s WHERE username=%s", (password_hash, username))
            return cur.rowcount > 0

    def update_db_user_role(self, username: str, role: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("UPDATE db_users SET role=%s WHERE username=%s", (role, username))
            return cur.rowcount > 0

    def get_user_totp(self, username: str) -> dict:
        from server.crypto import decrypt
        with self._connect() as conn:
            row = conn.execute(
                "SELECT totp_secret, totp_enabled FROM db_users WHERE username=%s",
                (username,),
            ).fetchone()
        if not row:
            return {"totp_secret": None, "totp_enabled": False}
        return {
            "totp_secret": decrypt(row["totp_secret"]),
            "totp_enabled": bool(row["totp_enabled"]),
        }

    def set_user_totp_secret(
        self, username: str, secret: str,
        role: str = "viewer", tenant_id: str = "default",
    ) -> None:
        from server.crypto import encrypt
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO db_users (username, password_hash, role, tenant_id)"
                " VALUES (%s, '__TOTP_ONLY__', %s, %s)"
                " ON CONFLICT (username) DO NOTHING",
                (username, role, tenant_id),
            )
            conn.execute(
                "UPDATE db_users SET totp_secret=%s, totp_enabled=0 WHERE username=%s",
                (encrypt(secret), username),
            )

    def enable_user_totp(self, username: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE db_users SET totp_enabled=1 WHERE username=%s",
                (username,),
            )

    def disable_user_totp(self, username: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE db_users SET totp_enabled=0, totp_secret=NULL WHERE username=%s",
                (username,),
            )

    # ------------------------------------------------------------------ #
    #  API KEYS
    # ------------------------------------------------------------------ #

    def save_api_key(self, agent_id: str, api_key: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO api_keys (agent_id, api_key) VALUES (%s,%s)
                   ON CONFLICT (agent_id) DO UPDATE SET api_key=EXCLUDED.api_key, created_at=NOW()""",
                (agent_id, api_key),
            )

    def get_api_key(self, agent_id: str) -> Optional[str]:
        with self._connect() as conn:
            row = conn.execute("SELECT api_key FROM api_keys WHERE agent_id=%s", (agent_id,)).fetchone()
        return row["api_key"] if row else None

    def get_all_api_keys(self) -> dict[str, str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT agent_id, api_key FROM api_keys").fetchall()
        return {r["agent_id"]: r["api_key"] for r in rows}

    def delete_api_key(self, agent_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM api_keys WHERE agent_id=%s", (agent_id,))

    # ------------------------------------------------------------------ #
    #  AUDIT LOG
    # ------------------------------------------------------------------ #

    def save_audit_event(self, actor: str, action: str, resource: str, detail: str = "", ip_address: str = "") -> None:
        import hashlib
        event_id = str(_uuid_mod.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (_AUDIT_CHAIN_LOCK_ID,))
            row = conn.execute(
                "SELECT entry_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous_hash = row["entry_hash"] if row else _AUDIT_CHAIN_GENESIS
            content = _audit_content(event_id, actor, action, resource, detail or "", ip_address or "", now, previous_hash)
            entry_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            conn.execute(
                "INSERT INTO audit_log "
                "(event_id, actor, action, resource, detail, ip_address, timestamp, previous_hash, entry_hash) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (event_id, actor, action, resource, detail, ip_address, now, previous_hash, entry_hash),
            )

    def get_audit_log(self, limit: int = 100, actor: str = "") -> list[dict]:
        with self._connect() as conn:
            if actor:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE actor=%s ORDER BY timestamp DESC LIMIT %s",
                    (actor, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT %s", (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    def verify_audit_chain(self) -> dict:
        """SHA-256 hash zincirini baştan sona doğrula. NIST SP 800-92 §3.2."""
        import hashlib
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, event_id, actor, action, resource, detail, ip_address, "
                "timestamp, previous_hash, entry_hash FROM audit_log ORDER BY id ASC"
            ).fetchall()
        if not rows:
            return {"valid": True, "checked": 0, "skipped": 0, "first_broken_at": None, "message": "Audit log boş"}

        expected_prev = _AUDIT_CHAIN_GENESIS
        checked = 0
        skipped = 0
        for row in rows:
            entry_hash = row["entry_hash"]
            if entry_hash is None:
                skipped += 1
                continue
            previous_hash = row["previous_hash"] or _AUDIT_CHAIN_GENESIS
            if previous_hash != expected_prev:
                return {
                    "valid": False,
                    "checked": checked,
                    "skipped": skipped,
                    "first_broken_at": row["id"],
                    "message": "Önceki hash uyuşmuyor — bir kayıt bozulmuş veya silinmiş",
                }
            ts = row["timestamp"]
            ts_str = ts.astimezone(timezone.utc).isoformat() if hasattr(ts, "astimezone") else str(ts)
            content = _audit_content(
                row["event_id"], row["actor"], row["action"], row["resource"],
                row["detail"] or "", row["ip_address"] or "", ts_str, previous_hash,
            )
            computed = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if computed != entry_hash:
                return {
                    "valid": False,
                    "checked": checked,
                    "skipped": skipped,
                    "first_broken_at": row["id"],
                    "message": "Hash uyuşmuyor — bir kayıt değiştirilmiş",
                }
            expected_prev = entry_hash
            checked += 1

        return {
            "valid": True,
            "checked": checked,
            "skipped": skipped,
            "first_broken_at": None,
            "message": f"Hash zinciri bütün — {checked} kayıt doğrulandı, {skipped} eski kayıt atlandı",
        }

    # ------------------------------------------------------------------ #
    #  TOKEN BLACKLIST
    # ------------------------------------------------------------------ #

    def blacklist_token(self, jti: str, expires_at: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO token_blacklist (jti, expires_at) VALUES (%s,%s) ON CONFLICT (jti) DO NOTHING",
                (jti, _dt(expires_at)),
            )

    def is_token_blacklisted(self, jti: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM token_blacklist WHERE jti=%s", (jti,)).fetchone()
        return row is not None

    def cleanup_expired_blacklist(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM token_blacklist WHERE expires_at < %s", (_now(),))
        return cur.rowcount

    # ------------------------------------------------------------------ #
    #  THREAT INTEL CACHE
    # ------------------------------------------------------------------ #

    def get_threat_intel(self, ip: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM threat_intel_cache WHERE ip=%s", (ip,)).fetchone()
        return dict(row) if row else None

    def save_threat_intel(self, ip: str, score: int, total_reports: int,
                          country_code: str, isp: str,
                          feodo_listed: bool = False, feodo_malware: str = "",
                          threatfox_score: int = 0, threatfox_malware: str = "",
                          greynoise_noise: bool = False, greynoise_riot: bool = False,
                          greynoise_classification: str = "",
                          composite_score: int = 0) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO threat_intel_cache
                     (ip, score, total_reports, country_code, isp,
                      feodo_listed, feodo_malware,
                      threatfox_score, threatfox_malware,
                      greynoise_noise, greynoise_riot, greynoise_classification,
                      composite_score, queried_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (ip) DO UPDATE SET
                       score=EXCLUDED.score, total_reports=EXCLUDED.total_reports,
                       country_code=EXCLUDED.country_code, isp=EXCLUDED.isp,
                       feodo_listed=EXCLUDED.feodo_listed, feodo_malware=EXCLUDED.feodo_malware,
                       threatfox_score=EXCLUDED.threatfox_score, threatfox_malware=EXCLUDED.threatfox_malware,
                       greynoise_noise=EXCLUDED.greynoise_noise, greynoise_riot=EXCLUDED.greynoise_riot,
                       greynoise_classification=EXCLUDED.greynoise_classification,
                       composite_score=EXCLUDED.composite_score,
                       queried_at=EXCLUDED.queried_at""",
                (ip, score, total_reports, country_code, isp,
                 feodo_listed, feodo_malware,
                 threatfox_score, threatfox_malware,
                 greynoise_noise, greynoise_riot, greynoise_classification,
                 composite_score, _now()),
            )

    # ------------------------------------------------------------------ #
    #  TOPOLOGY
    # ------------------------------------------------------------------ #

    def upsert_topology_node(
        self, device_id: str, name: str, ip: str = "", device_type: str = "unknown",
        vendor: str = "", os_info: str = "", layer: int = 3,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO topology_nodes (device_id, name, ip, type, vendor, os_info, layer, updated_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (device_id) DO UPDATE SET
                       name=%s, ip=%s, type=%s, vendor=%s, os_info=%s, layer=%s, updated_at=%s""",
                (device_id, name, ip, device_type, vendor, os_info, layer, _now(),
                 name, ip, device_type, vendor, os_info, layer, _now()),
            )

    def upsert_topology_edge(self, src_id: str, dst_id: str, link_type: str = "ip", discovered: str = "arp") -> None:
        canonical_src, canonical_dst = sorted([src_id, dst_id])
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO topology_edges (src_id, dst_id, link_type, discovered, updated_at)
                   VALUES (%s,%s,%s,%s,%s)
                   ON CONFLICT (src_id, dst_id, link_type) DO UPDATE SET
                       discovered=EXCLUDED.discovered, updated_at=EXCLUDED.updated_at""",
                (canonical_src, canonical_dst, link_type, discovered, _now()),
            )

    def get_topology_graph(self) -> dict:
        with self._connect() as conn:
            nodes = [dict(r) for r in conn.execute("SELECT * FROM topology_nodes").fetchall()]
            edges = [dict(r) for r in conn.execute("SELECT * FROM topology_edges").fetchall()]
        return {"nodes": nodes, "edges": edges}

    def clear_topology(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM topology_edges")
            conn.execute("DELETE FROM topology_nodes")

    # ------------------------------------------------------------------ #
    #  INCIDENTS
    # ------------------------------------------------------------------ #

    def create_incident(self, incident, tenant_id: str = "default") -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO incidents
                   (incident_id, title, description, severity, status,
                    assigned_to, source_event_id, source_type,
                    created_by, notes, rule_id, group_value, group_by_field,
                    priority_score, closure_note, tenant_id)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    incident.incident_id, incident.title, incident.description,
                    incident.severity, incident.status.value,
                    incident.assigned_to, incident.source_event_id, incident.source_type,
                    incident.created_by, incident.notes,
                    incident.rule_id, incident.group_value,
                    getattr(incident, "group_by_field", "source_ip"),
                    getattr(incident, "priority_score", 0),
                    getattr(incident, "closure_note", ""),
                    tenant_id,
                ),
            )

    def find_open_incident_for_rule(self, rule_id: str, group_value: str) -> Optional[str]:
        with self._connect() as conn:
            row = conn.execute(
                """SELECT incident_id FROM incidents
                   WHERE rule_id=%s AND group_value=%s AND status IN ('open','investigating')
                   ORDER BY created_at DESC LIMIT 1""",
                (rule_id, group_value),
            ).fetchone()
        return row["incident_id"] if row else None

    def escalate_incident_severity(self, incident_id: str, new_severity: str) -> bool:
        row = self.get_incident(incident_id)
        if not row:
            return False
        if self._SEV_ORDER.get(new_severity, 0) <= self._SEV_ORDER.get(row["severity"], 0):
            return False
        with self._connect() as conn:
            conn.execute(
                "UPDATE incidents SET severity=%s, updated_at=%s WHERE incident_id=%s",
                (new_severity, _now(), incident_id),
            )
        return True

    def add_incident_event(
        self, incident_id: str, event_id: str, event_action: str,
        severity: str, message: str, occurred_at: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO incident_events
                   (incident_id, event_id, event_action, severity, message, occurred_at)
                   VALUES (%s,%s,%s,%s,%s,%s)""",
                (incident_id, event_id, event_action, severity, message, _dt(occurred_at)),
            )

    def get_incident_events(self, incident_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incident_events WHERE incident_id=%s ORDER BY occurred_at ASC",
                (incident_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_to: Optional[str] = None,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list[dict]:
        clauses, params = ["1=1"], []
        if status:
            clauses.append("status=%s"); params.append(status)
        if severity:
            clauses.append("severity=%s"); params.append(severity)
        if assigned_to:
            clauses.append("assigned_to=%s"); params.append(assigned_to)
        if tenant_id is not None:
            clauses.append("tenant_id=%s"); params.append(tenant_id)
        params.append(limit)
        where = "WHERE " + " AND ".join(clauses)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM incidents {where} ORDER BY created_at DESC LIMIT %s",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    def get_incident(self, incident_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id=%s", (incident_id,)).fetchone()
        return dict(row) if row else None

    def resolve_all_incidents(self, tenant_id: Optional[str] = None) -> int:
        now = _now()
        clauses = ["status IN ('open','investigating')"]
        params: list = [now, now, "Toplu çözümleme"]
        if tenant_id is not None:
            clauses.append("tenant_id=%s"); params.append(tenant_id)
        where = "WHERE " + " AND ".join(clauses)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE incidents SET status='resolved', resolved_at=%s, updated_at=%s, closure_note=%s {where}",
                params,
            )
            return cur.rowcount

    def update_incident(
        self,
        incident_id: str,
        status: Optional[str] = None,
        assigned_to: Optional[str] = None,
        notes: Optional[str] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        closure_note: Optional[str] = None,
        priority_score: Optional[int] = None,
    ) -> bool:
        fields, params = [], []
        now = _now()
        if status is not None:
            fields.append("status=%s"); params.append(status)
            if status == "resolved":
                fields.append("resolved_at=%s"); params.append(now)
            if status == "investigating":
                fields.append("acknowledged_at=COALESCE(acknowledged_at,%s)"); params.append(now)
        if assigned_to is not None:
            fields.append("assigned_to=%s"); params.append(assigned_to)
        if notes is not None:
            fields.append("notes=%s"); params.append(notes)
        if title is not None:
            fields.append("title=%s"); params.append(title)
        if description is not None:
            fields.append("description=%s"); params.append(description)
        if closure_note is not None:
            fields.append("closure_note=%s"); params.append(closure_note)
        if priority_score is not None:
            fields.append("priority_score=%s"); params.append(priority_score)
        if not fields:
            return False
        fields.append("updated_at=%s"); params.append(now)
        params.append(incident_id)
        with self._connect() as conn:
            cur = conn.execute(
                f"UPDATE incidents SET {', '.join(fields)} WHERE incident_id=%s",
                params,
            )
            return cur.rowcount > 0

    def delete_incident(self, incident_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM incidents WHERE incident_id=%s", (incident_id,))
            return cur.rowcount > 0

    def count_incidents(self, status: Optional[str] = None, tenant_id: Optional[str] = None) -> int:
        clauses, params = [], []
        if status:
            clauses.append("status=%s"); params.append(status)
        if tenant_id is not None:
            clauses.append("tenant_id=%s"); params.append(tenant_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as conn:
            row = conn.execute(f"SELECT COUNT(*) FROM incidents {where}", params).fetchone()
        return list(row.values())[0] if row else 0

    # ------------------------------------------------------------------ #
    #  RETENTION — dinamik tablo temizliği
    # ------------------------------------------------------------------ #

    def fetch_table_rows_before(
        self,
        table: str,
        ts_col: str,
        cutoff: datetime,
        extra_where: str = "",
    ) -> list[dict]:
        """cutoff öncesi satırları döner (arşivleme için). Yalnızca iç retention kodu çağırır."""
        if table not in _RETENTION_ALLOWED or _RETENTION_ALLOWED[table] != ts_col:
            raise ValueError(f"fetch_table_rows_before: izin verilmeyen tablo/kolon '{table}.{ts_col}'")
        where = f"{ts_col} < %s"
        if extra_where:
            where += f" AND {extra_where}"
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM {table} WHERE {where}", (cutoff,)
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_table_rows_before(
        self,
        table: str,
        ts_col: str,
        cutoff: datetime,
        extra_where: str = "",
    ) -> int:
        """cutoff öncesi satırları siler, silinen satır sayısını döner. Yalnızca iç retention kodu çağırır."""
        if table not in _RETENTION_ALLOWED or _RETENTION_ALLOWED[table] != ts_col:
            raise ValueError(f"delete_table_rows_before: izin verilmeyen tablo/kolon '{table}.{ts_col}'")
        where = f"{ts_col} < %s"
        if extra_where:
            where += f" AND {extra_where}"
        with self._connect() as conn:
            cur = conn.execute(
                f"DELETE FROM {table} WHERE {where}", (cutoff,)
            )
            return cur.rowcount

    # ------------------------------------------------------------------ #
    #  NO-OP COMPATIBILITY (SQLite-only methods not needed in PostgreSQL)
    # ------------------------------------------------------------------ #

    def _init_fts(self) -> None:
        pass  # GIN index Alembic migration'da oluşturulur


def _fp_row_to_dict(row: dict) -> dict:
    """fp_rules satırını JSON-serializable dict'e çevir."""
    d = dict(row)
    for key in ("created_at", "expires_at"):
        if d.get(key) and hasattr(d[key], "isoformat"):
            d[key] = d[key].isoformat()
    return d


db: Optional[DatabaseManager] = DatabaseManager(DATABASE_URL) if os.getenv("DATABASE_URL") else None
