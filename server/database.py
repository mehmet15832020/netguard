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
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Optional

_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){1,3}$')

from shared.models import (
    Alert, AlertSeverity, AlertStatus,
    SecurityEvent, SecurityEventType,
    RawLog, NormalizedLog, LogSourceType, LogCategory,
    CorrelatedEvent, ParseStatus,
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
    event_action   TEXT NOT NULL,
    severity     TEXT NOT NULL,
    source_ip    TEXT,
    username     TEXT,
    message      TEXT NOT NULL,
    raw_data     TEXT,
    occurred_at  TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sec_type    ON security_events(event_action);
CREATE INDEX IF NOT EXISTS idx_sec_agent   ON security_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_sec_time    ON security_events(occurred_at);
CREATE INDEX IF NOT EXISTS idx_sec_srcip   ON security_events(source_ip);
"""


_CREATE_RAW_LOGS = """
CREATE TABLE IF NOT EXISTS raw_logs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_id             TEXT UNIQUE NOT NULL,
    source_type        TEXT,
    observer_hostname        TEXT NOT NULL,
    received_at        TEXT NOT NULL,
    raw_content        TEXT NOT NULL,
    parse_status       TEXT NOT NULL DEFAULT 'pending',
    normalized_log_id  TEXT
);
CREATE INDEX IF NOT EXISTS idx_raw_host     ON raw_logs(observer_hostname);
CREATE INDEX IF NOT EXISTS idx_raw_received ON raw_logs(received_at);
"""

_CREATE_NORMALIZED_LOGS = """
CREATE TABLE IF NOT EXISTS normalized_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id       TEXT UNIQUE NOT NULL,
    raw_id       TEXT NOT NULL,
    source_type  TEXT NOT NULL,
    observer_hostname  TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    received_at  TEXT NOT NULL,
    severity     TEXT NOT NULL,
    event_category     TEXT NOT NULL,
    event_action   TEXT NOT NULL,
    source_ip            TEXT,
    destination_ip       TEXT,
    source_hostname      TEXT,
    destination_hostname TEXT,
    source_port          INTEGER,
    destination_port     INTEGER,
    network_protocol     TEXT,
    username     TEXT,
    message      TEXT NOT NULL,
    tags         TEXT NOT NULL DEFAULT '[]',
    extra        TEXT NOT NULL DEFAULT '{}',
    network_bytes        INTEGER,
    processed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_norm_timestamp   ON normalized_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_norm_source_type ON normalized_logs(source_type);
CREATE INDEX IF NOT EXISTS idx_norm_category    ON normalized_logs(event_category);
CREATE INDEX IF NOT EXISTS idx_norm_src_ip      ON normalized_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_norm_event_type  ON normalized_logs(event_action);
CREATE INDEX IF NOT EXISTS idx_norm_corr_query  ON normalized_logs(event_action, timestamp, source_ip);
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

_CREATE_SNMP_POLL_HISTORY = """
CREATE TABLE IF NOT EXISTS snmp_poll_history (
    host      TEXT NOT NULL,
    if_index  TEXT NOT NULL,
    if_name   TEXT NOT NULL,
    polled_at TEXT NOT NULL,
    hc_in     INTEGER NOT NULL DEFAULT 0,
    hc_out    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host, if_index)
);
"""

_CREATE_SERVICE_CHECKS = """
CREATE TABLE IF NOT EXISTS service_checks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  TEXT NOT NULL,
    check_type TEXT NOT NULL,
    target     TEXT NOT NULL,
    port       INTEGER,
    status     TEXT NOT NULL,
    rtt_ms     REAL,
    checked_at TEXT NOT NULL,
    details    TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_svc_device  ON service_checks(device_id);
CREATE INDEX IF NOT EXISTS idx_svc_checked ON service_checks(checked_at);
"""

_CREATE_DEVICES = """
CREATE TABLE IF NOT EXISTS devices (
    device_id      TEXT PRIMARY KEY,
    name           TEXT NOT NULL,
    ip             TEXT DEFAULT '',
    mac            TEXT DEFAULT '',
    type           TEXT NOT NULL DEFAULT 'discovered',
    vendor         TEXT DEFAULT '',
    os_info        TEXT DEFAULT '',
    status         TEXT DEFAULT 'unknown',
    first_seen     TEXT NOT NULL,
    last_seen      TEXT,
    snmp_community TEXT DEFAULT '',
    snmp_version   TEXT DEFAULT 'v2c',
    risk_score     INTEGER DEFAULT 0,
    segment        TEXT DEFAULT '',
    notes          TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_devices_type   ON devices(type);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_ip     ON devices(ip);
"""

_CREATE_API_KEYS = """
CREATE TABLE IF NOT EXISTS api_keys (
    agent_id   TEXT PRIMARY KEY,
    api_key    TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

_AUDIT_CHAIN_GENESIS = "0" * 64


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


_CREATE_AUDIT_LOG = """
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT UNIQUE NOT NULL,
    actor         TEXT NOT NULL,
    action        TEXT NOT NULL,
    resource      TEXT NOT NULL,
    detail        TEXT,
    ip_address    TEXT,
    timestamp     TEXT NOT NULL,
    previous_hash TEXT,
    entry_hash    TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_actor     ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
"""

_CREATE_THREAT_INTEL = """
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ip                       TEXT PRIMARY KEY,
    score                    INTEGER NOT NULL,
    total_reports            INTEGER NOT NULL DEFAULT 0,
    country_code             TEXT,
    isp                      TEXT,
    feodo_listed             INTEGER NOT NULL DEFAULT 0,
    feodo_malware            TEXT,
    threatfox_score          INTEGER NOT NULL DEFAULT 0,
    threatfox_malware        TEXT,
    greynoise_noise          INTEGER NOT NULL DEFAULT 0,
    greynoise_riot           INTEGER NOT NULL DEFAULT 0,
    greynoise_classification TEXT,
    composite_score          INTEGER NOT NULL DEFAULT 0,
    queried_at               TEXT NOT NULL
);
"""

_CREATE_TOKEN_BLACKLIST = """
CREATE TABLE IF NOT EXISTS token_blacklist (
    jti        TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL
);
"""

_CREATE_TOPOLOGY = """
CREATE TABLE IF NOT EXISTS topology_nodes (
    device_id   TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    ip          TEXT DEFAULT '',
    type        TEXT DEFAULT 'unknown',
    vendor      TEXT DEFAULT '',
    os_info     TEXT DEFAULT '',
    layer       INTEGER DEFAULT 3,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS topology_edges (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    src_id       TEXT NOT NULL,
    dst_id       TEXT NOT NULL,
    link_type    TEXT NOT NULL DEFAULT 'ip',
    discovered   TEXT NOT NULL DEFAULT 'arp',
    updated_at   TEXT NOT NULL,
    UNIQUE(src_id, dst_id, link_type)
);
CREATE INDEX IF NOT EXISTS idx_topo_edges_src ON topology_edges(src_id);
CREATE INDEX IF NOT EXISTS idx_topo_edges_dst ON topology_edges(dst_id);
"""

_CREATE_INCIDENTS_BASE = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    description     TEXT DEFAULT '',
    severity        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open',
    assigned_to     TEXT,
    source_event_id TEXT,
    source_type     TEXT,
    created_by      TEXT NOT NULL,
    notes           TEXT DEFAULT '',
    rule_id         TEXT,
    group_value     TEXT,
    priority_score  INTEGER DEFAULT 0,
    closure_note    TEXT DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    resolved_at     TEXT,
    acknowledged_at TEXT
);
"""

_CREATE_INCIDENTS_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_incidents_status      ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity    ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created     ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_rule_group  ON incidents(rule_id, group_value);
"""

_CREATE_INCIDENT_EVENTS = """
CREATE TABLE IF NOT EXISTS incident_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    event_id    TEXT NOT NULL,
    event_action  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    added_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inc_events_incident ON incident_events(incident_id);
CREATE INDEX IF NOT EXISTS idx_inc_events_occurred ON incident_events(occurred_at);
"""

_CREATE_CORRELATED_EVENTS = """
CREATE TABLE IF NOT EXISTS correlated_events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    corr_id          TEXT UNIQUE NOT NULL,
    rule_id          TEXT NOT NULL,
    rule_name        TEXT NOT NULL,
    event_action       TEXT NOT NULL,
    severity         TEXT NOT NULL,
    group_value      TEXT NOT NULL,
    matched_count    INTEGER NOT NULL,
    window_seconds   INTEGER NOT NULL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    message          TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    mitre_techniques TEXT DEFAULT '',
    mitre_tactics    TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_corr_rule_id     ON correlated_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_corr_event_type  ON correlated_events(event_action);
CREATE INDEX IF NOT EXISTS idx_corr_group_value ON correlated_events(group_value);
CREATE INDEX IF NOT EXISTS idx_corr_created_at  ON correlated_events(created_at);
"""

_CREATE_TENANTS = """
CREATE TABLE IF NOT EXISTS tenants (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    is_active  INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
"""

_CREATE_SITES = """
CREATE TABLE IF NOT EXISTS sites (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id),
    name       TEXT NOT NULL,
    location   TEXT NOT NULL DEFAULT '',
    tz         TEXT NOT NULL DEFAULT 'UTC',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sites_tenant ON sites(tenant_id);
"""

_CREATE_DB_USERS = """
CREATE TABLE IF NOT EXISTS db_users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    tenant_id     TEXT REFERENCES tenants(id),
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_db_users_tenant ON db_users(tenant_id);
"""

_CREATE_FTS5 = """
CREATE VIRTUAL TABLE IF NOT EXISTS normalized_logs_fts USING fts5(
    message,
    source_ip,
    destination_ip,
    observer_hostname,
    username,
    event_action,
    content='normalized_logs',
    content_rowid='id'
);
"""

_CREATE_FTS5_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS fts_insert AFTER INSERT ON normalized_logs BEGIN
    INSERT INTO normalized_logs_fts(rowid, message, source_ip, destination_ip, observer_hostname, username, event_action)
    VALUES (new.id, new.message, new.source_ip, new.destination_ip, new.observer_hostname, new.username, new.event_action);
END;

CREATE TRIGGER IF NOT EXISTS fts_delete AFTER DELETE ON normalized_logs BEGIN
    INSERT INTO normalized_logs_fts(normalized_logs_fts, rowid, message, source_ip, destination_ip, observer_hostname, username, event_action)
    VALUES ('delete', old.id, old.message, old.source_ip, old.destination_ip, old.observer_hostname, old.username, old.event_action);
END;
"""

_CREATE_CHAIN_STATE = """
CREATE TABLE IF NOT EXISTS attack_chain_state (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip      TEXT NOT NULL,
    stage       TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_chain_state_src_ip ON attack_chain_state(source_ip);
CREATE INDEX IF NOT EXISTS idx_chain_state_occurred ON attack_chain_state(occurred_at);
"""

_CREATE_ASSET_BASELINES = """
CREATE TABLE IF NOT EXISTS asset_baselines (
    source_ip             TEXT NOT NULL,
    tenant_id             TEXT NOT NULL DEFAULT 'default',
    first_seen_at         TEXT NOT NULL,
    last_seen_at          TEXT NOT NULL,
    avg_events_per_hour   REAL NOT NULL DEFAULT 0,
    typical_ports         TEXT NOT NULL DEFAULT '[]',
    typical_destinations  TEXT NOT NULL DEFAULT '[]',
    typical_event_actions TEXT NOT NULL DEFAULT '[]',
    sample_hours          INTEGER NOT NULL DEFAULT 0,
    updated_at            TEXT NOT NULL,
    PRIMARY KEY (source_ip, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_baselines_tenant ON asset_baselines(tenant_id);
"""

_CREATE_FP_RULES = """
CREATE TABLE IF NOT EXISTS fp_rules (
    fp_rule_id       TEXT PRIMARY KEY,
    event_action     TEXT,
    source_ip        TEXT,
    destination_ip   TEXT,
    destination_port TEXT,
    observer_hostname TEXT,
    tenant_id        TEXT NOT NULL DEFAULT 'default',
    reason           TEXT NOT NULL,
    created_by       TEXT NOT NULL DEFAULT 'admin',
    created_at       TEXT NOT NULL,
    expires_at       TEXT,
    is_active        INTEGER NOT NULL DEFAULT 1,
    hit_count        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_fp_rules_tenant_active ON fp_rules(tenant_id, is_active);
"""

_CREATE_BLOCKED_IPS = """
CREATE TABLE IF NOT EXISTS blocked_ips (
    block_id          TEXT PRIMARY KEY,
    ip                TEXT NOT NULL,
    reason            TEXT NOT NULL DEFAULT '',
    blocked_at        TEXT NOT NULL,
    blocked_by        TEXT NOT NULL,
    is_active         INTEGER NOT NULL DEFAULT 1,
    source_incident_id TEXT,
    provider          TEXT NOT NULL DEFAULT 'opnsense',
    unblocked_at      TEXT,
    unblocked_by      TEXT,
    tenant_id         TEXT NOT NULL DEFAULT 'default',
    expires_at        TEXT,
    offense_count     INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_blocked_ip        ON blocked_ips(ip);
CREATE INDEX IF NOT EXISTS idx_blocked_active    ON blocked_ips(is_active);
CREATE INDEX IF NOT EXISTS idx_blocked_tenant    ON blocked_ips(tenant_id);
CREATE INDEX IF NOT EXISTS idx_blocked_incident  ON blocked_ips(source_incident_id);
"""

_CREATE_SCHEMA_VERSION = """
CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
"""

CURRENT_SCHEMA_VERSION = 1


class DatabaseManager:
    """
    Thread-safe SQLite yöneticisi.
    Her işlem kendi connection'ını açar — WAL mode ile eşzamanlı okuma desteklenir.
    """

    def __init__(self, db_path: str = DB_PATH):
        self._path = db_path
        self._lock = Lock()
        self._init_db()

    def get_schema_version(self) -> int:
        """Mevcut schema versiyonunu döndür. Tablo yoksa 0."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT MAX(version) FROM schema_version"
                ).fetchone()
                return row[0] or 0
        except Exception:
            return 0

    def _init_fts(self) -> None:
        """FTS5 virtual table ve trigger'ları oluştur; mevcut verilerle indexi doldur."""
        with self._lock:
            with self._connect() as conn:
                conn.executescript(_CREATE_FTS5)
                conn.executescript(_CREATE_FTS5_TRIGGERS)
                count = conn.execute("SELECT COUNT(*) FROM normalized_logs_fts").fetchone()[0]
                if count == 0:
                    conn.execute("""
                        INSERT INTO normalized_logs_fts(rowid, message, source_ip, destination_ip, observer_hostname, username, event_action)
                        SELECT id, message, source_ip, destination_ip, observer_hostname, username, event_action
                        FROM normalized_logs
                    """)
                    rebuilt = conn.execute("SELECT COUNT(*) FROM normalized_logs_fts").fetchone()[0]
                    if rebuilt > 0:
                        logger.info(f"FTS5 indexi yeniden oluşturuldu: {rebuilt} kayıt")

    def search_logs(
        self,
        query: str,
        source_type: Optional[str] = None,
        event_category: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list:
        """Full-text arama: message, source_ip, destination_ip, observer_hostname, username, event_action içinde ara."""
        q = query.strip()
        if not q:
            return self.get_normalized_logs(
                source_type=source_type, event_category=event_category, limit=limit, tenant_id=tenant_id
            )

        clauses: list[str] = []
        params: list = []

        if _IP_RE.match(q):
            clauses.append("(source_ip LIKE ? OR destination_ip LIKE ? OR observer_hostname LIKE ?)")
            pattern = f"{q}%"
            params.extend([pattern, pattern, pattern])
        else:
            safe_q = q.replace('"', '""')
            clauses.append(
                "id IN (SELECT rowid FROM normalized_logs_fts WHERE normalized_logs_fts MATCH ?)"
            )
            params.append(safe_q)

        if source_type:
            clauses.append("source_type = ?")
            params.append(source_type)
        if event_category:
            clauses.append("event_category = ?")
            params.append(event_category)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)

        where = "WHERE " + " AND ".join(clauses)
        params.append(limit)

        try:
            with self._connect() as conn:
                rows = conn.execute(
                    f"SELECT * FROM normalized_logs {where} ORDER BY timestamp DESC LIMIT ?",
                    params,
                ).fetchall()
            return [self._row_to_normalized_log(r) for r in rows]
        except sqlite3.OperationalError:
            return []

    def _apply_schema_version(self, version: int, description: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO schema_version (version, applied_at, description) VALUES (?,?,?)",
                (version, now, description),
            )

    def _init_db(self) -> None:
        """Tabloları oluştur, yoksa geç."""
        with self._connect() as conn:
            conn.executescript(_CREATE_SCHEMA_VERSION)
            conn.executescript(_CREATE_ALERTS)
            conn.executescript(_CREATE_SECURITY_EVENTS)
            conn.executescript(_CREATE_RAW_LOGS)
            conn.executescript(_CREATE_NORMALIZED_LOGS)
            conn.executescript(_CREATE_CORRELATED_EVENTS)
            conn.executescript(_CREATE_SNMP_DEVICES)
            conn.executescript(_CREATE_SNMP_POLL_HISTORY)
            conn.executescript(_CREATE_SERVICE_CHECKS)
            conn.executescript(_CREATE_DEVICES)
            conn.executescript(_CREATE_API_KEYS)
            conn.executescript(_CREATE_AUDIT_LOG)
            conn.executescript(_CREATE_THREAT_INTEL)
            conn.executescript(_CREATE_TOKEN_BLACKLIST)
            conn.executescript(_CREATE_TOPOLOGY)
            conn.executescript(_CREATE_INCIDENTS_BASE)
            conn.executescript(_CREATE_TENANTS)
            conn.executescript(_CREATE_SITES)
            conn.executescript(_CREATE_DB_USERS)
        self._migrate_incidents_columns()
        with self._connect() as conn:
            conn.executescript(_CREATE_INCIDENTS_INDEXES)
            conn.executescript(_CREATE_INCIDENT_EVENTS)
        with self._connect() as conn:
            conn.executescript(_CREATE_CHAIN_STATE)
        with self._connect() as conn:
            conn.executescript(_CREATE_ASSET_BASELINES)
        with self._connect() as conn:
            conn.executescript(_CREATE_FP_RULES)
        with self._connect() as conn:
            conn.executescript(_CREATE_BLOCKED_IPS)
        self._migrate_snmp_to_devices()
        self._migrate_snmpv3_columns()
        self._migrate_api_keys_to_hashed()
        self._migrate_raw_logs_parse_status()
        self._migrate_normalized_logs_columns()
        self._migrate_ecs_field_rename()
        self._migrate_audit_hash_columns()
        self._migrate_correlated_events_mitre()
        self._migrate_tenant_id()
        self._migrate_dns_hostname_columns()
        self._migrate_incident_v1_4_columns()
        self._migrate_blocked_ips_expires_at()
        self._migrate_blocked_ips_offense_count()
        self._migrate_db_users_totp_columns()
        self.ensure_default_tenant()
        self._init_fts()
        self._apply_schema_version(CURRENT_SCHEMA_VERSION, "initial schema + tenant_id migrations")
        logger.info(f"SQLite başlatıldı: {Path(self._path).resolve()} (schema v{self.get_schema_version()})")

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
        agent_id: Optional[str] = None,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list[Alert]:
        """Alert listesini döndür. Status, agent_id ve tenant_id filtresi opsiyonel."""
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if agent_id is not None:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY triggered_at DESC LIMIT ?",
                params,
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

    def resolve_all_alerts(self, tenant_id: str = "default") -> int:
        """Tüm aktif alertları resolved yapar. Etkilenen satır sayısını döndürür."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE alerts SET status='resolved', resolved_at=? WHERE status='active' AND tenant_id=?",
                    (now, tenant_id),
                )
                return cur.rowcount

    # ------------------------------------------------------------------ #
    #  SECURITY EVENTS
    # ------------------------------------------------------------------ #

    def save_security_event(self, event: SecurityEvent, tenant_id: str = "default") -> None:
        """Güvenlik olayını kaydet. Duplicate event_id'yi sessizce yoksay."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO security_events
                        (event_id, agent_id, hostname, event_action, severity,
                         source_ip, username, message, raw_data,
                         occurred_at, created_at, tenant_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    event.occurred_at.isoformat(),
                    event.created_at.isoformat(),
                    tenant_id,
                ))

    def get_security_events(
        self,
        event_action: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list[SecurityEvent]:
        """Güvenlik olaylarını filtreli getir."""
        clauses, params = [], []
        if event_action:
            clauses.append("event_action = ?")
            params.append(event_action)
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM security_events {where} ORDER BY occurred_at DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def count_security_events(self, event_action: Optional[str] = None) -> int:
        """Olay tipine göre toplam kayıt sayısı."""
        with self._connect() as conn:
            if event_action:
                row = conn.execute(
                    "SELECT COUNT(*) FROM security_events WHERE event_action = ?",
                    (event_action,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()
        return row[0] if row else 0

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
                  AND event_action = ?
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
            event_action  = SecurityEventType(row["event_action"]),
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
                        (raw_id, source_type, observer_hostname, received_at,
                         raw_content, parse_status, normalized_log_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    raw.raw_id,
                    raw.source_type.value if raw.source_type else None,
                    raw.observer_hostname,
                    raw.received_at.isoformat(),
                    raw.raw_content,
                    raw.parse_status.value,
                    raw.normalized_log_id,
                ))

    def mark_raw_normalized(self, raw_id: str, normalized_log_id: str) -> None:
        """Ham logu normalize edildi olarak işaretle."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE raw_logs SET parse_status=?, normalized_log_id=? WHERE raw_id=?",
                    (ParseStatus.SUCCESS.value, normalized_log_id, raw_id),
                )

    def mark_raw_parse_failed(self, raw_id: str) -> None:
        """Ham logu parse edilemedi olarak işaretle."""
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE raw_logs SET parse_status=? WHERE raw_id=?",
                    (ParseStatus.FAILED.value, raw_id),
                )

    def get_unnormalized_raw_logs(self, limit: int = 100) -> list[RawLog]:
        """Henüz işlenmemiş (pending) ham logları getir."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM raw_logs WHERE parse_status=? ORDER BY received_at ASC LIMIT ?",
                (ParseStatus.PENDING.value, limit),
            ).fetchall()
        return [self._row_to_raw_log(r) for r in rows]

    def _row_to_raw_log(self, row: sqlite3.Row) -> RawLog:
        raw_status = row["parse_status"] if "parse_status" in row.keys() else None
        return RawLog(
            raw_id            = row["raw_id"],
            source_type       = LogSourceType(row["source_type"]) if row["source_type"] else None,
            observer_hostname       = row["observer_hostname"],
            received_at       = datetime.fromisoformat(row["received_at"]),
            raw_content       = row["raw_content"],
            parse_status      = ParseStatus(raw_status) if raw_status else ParseStatus.PENDING,
            normalized_log_id = row["normalized_log_id"],
        )

    # ------------------------------------------------------------------ #
    #  NORMALIZED LOGS
    # ------------------------------------------------------------------ #

    def save_normalized_log(self, log: NormalizedLog, tenant_id: str = "default") -> None:
        """Normalize edilmiş logu kaydet."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO normalized_logs
                        (log_id, raw_id, source_type, observer_hostname, timestamp,
                         received_at, severity, event_category, event_action,
                         source_ip, destination_ip, source_hostname, destination_hostname,
                         source_port, destination_port, network_protocol,
                         username, message, tags, extra, network_bytes, processed_at, tenant_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    log.log_id,
                    log.raw_id,
                    log.source_type.value,
                    log.observer_hostname,
                    log.timestamp.isoformat(),
                    log.received_at.isoformat(),
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
                    log.processed_at.isoformat(),
                    tenant_id,
                ))

    def update_log_hostnames(
        self,
        log_id: str,
        src_host: Optional[str],
        dst_host: Optional[str],
    ) -> bool:
        """
        DNS arka plan çözümlemesi tamamlandığında hostname kolonlarını güncelle.
        True: kayıt güncellendi. False: log_id bulunamadı (retention ile silinmiş olabilir).
        """
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE normalized_logs SET source_hostname = ?, destination_hostname = ? WHERE log_id = ?",
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
        """Normalize logları filtreli getir — timestamp'e göre sıralı."""
        clauses, params = [], []
        if source_type:
            clauses.append("source_type = ?")
            params.append(source_type)
        if event_category:
            clauses.append("event_category = ?")
            params.append(event_category)
        if source_ip:
            clauses.append("source_ip = ?")
            params.append(source_ip)
        if destination_ip:
            clauses.append("destination_ip = ?")
            params.append(destination_ip)
        if network_protocol:
            clauses.append("network_protocol = ?")
            params.append(network_protocol)
        if event_action:
            clauses.append("event_action = ?")
            params.append(event_action)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)

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
        event_action_prefix: str,
        group_by: str,
        group_value: str,
        since_iso: str,
        severity: Optional[str] = None,
    ) -> list[NormalizedLog]:
        """
        Korelasyon için: belirli zaman penceresindeki eşleşen normalize logları getir.
        event_action_prefix ile LIKE sorgusu yapılır (örn. 'wazuh_rule_' her wazuh kuralını yakalar).
        """
        group_col = "source_ip" if group_by == "source_ip" else "observer_hostname"
        params = [f"{event_action_prefix}%", group_value, since_iso]
        severity_clause = ""
        if severity:
            severity_clause = "AND severity = ?"
            params.append(severity)

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM normalized_logs
                WHERE event_action LIKE ?
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
            observer_hostname  = row["observer_hostname"],
            timestamp    = datetime.fromisoformat(row["timestamp"]),
            received_at  = datetime.fromisoformat(row["received_at"]),
            severity     = row["severity"],
            event_category     = LogCategory(row["event_category"]),
            event_action   = row["event_action"],
            source_ip            = row["source_ip"],
            destination_ip       = row["destination_ip"],
            source_hostname      = row["source_hostname"]      if "source_hostname"      in row.keys() else None,
            destination_hostname = row["destination_hostname"] if "destination_hostname" in row.keys() else None,
            source_port          = row["source_port"],
            destination_port     = row["destination_port"],
            network_protocol     = row["network_protocol"]     if "network_protocol"     in row.keys() else None,
            username         = row["username"],
            message      = row["message"],
            tags         = json.loads(row["tags"]),
            processed_at = datetime.fromisoformat(row["processed_at"]),
        )


    def get_log_volume(self, range: str = "24h", tenant_id: Optional[str] = None) -> list[dict]:
        """Saatlik log hacmini döner: [{t, c}, ...]"""
        hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}.get(range, 24)
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        params: list = [since]
        tenant_clause = ""
        if tenant_id is not None:
            tenant_clause = "AND tenant_id = ?"
            params.append(tenant_id)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT strftime('%Y-%m-%dT%H:00:00Z', received_at) AS t,
                       COUNT(*) AS c
                FROM normalized_logs
                WHERE received_at >= ? {tenant_clause}
                GROUP BY t
                ORDER BY t
                """,
                params,
            ).fetchall()
        return [{"t": r["t"], "c": r["c"]} for r in rows]

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
            since = (
                datetime.now(timezone.utc) - timedelta(seconds=event.window_seconds)
            ).isoformat()
            with self._connect() as conn:
                existing = conn.execute(
                    """
                    SELECT corr_id FROM correlated_events
                    WHERE rule_id = ? AND group_value = ?
                      AND created_at >= ?
                    LIMIT 1
                    """,
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
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.corr_id,
                    event.rule_id,
                    event.rule_name,
                    event.event_action,
                    event.severity,
                    event.group_value,
                    event.matched_count,
                    event.window_seconds,
                    event.first_seen.isoformat(),
                    event.last_seen.isoformat(),
                    event.message,
                    event.created_at.isoformat(),
                    ",".join(event.mitre_techniques),
                    ",".join(event.mitre_tactics),
                ))
                return True

    def save_chain_stage(self, source_ip: str, stage: str, occurred_at: "datetime", tenant_id: str = "default") -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO attack_chain_state (source_ip, stage, occurred_at, tenant_id) VALUES (?, ?, ?, ?)",
                    (source_ip, stage, occurred_at.isoformat(), tenant_id),
                )

    def get_active_chain_stages(self, window_seconds: int = 1800) -> dict:
        from datetime import datetime, timedelta, timezone
        from collections import defaultdict
        since = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT source_ip, stage, occurred_at FROM attack_chain_state WHERE occurred_at >= ? ORDER BY occurred_at",
                (since,),
            ).fetchall()
        result: dict = defaultdict(lambda: defaultdict(list))
        for row in rows:
            dt_str = row["occurred_at"]
            try:
                dt = datetime.fromisoformat(dt_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            result[row["source_ip"]][row["stage"]].append(dt)
        return result

    def purge_old_chain_stages(self, window_seconds: int = 1800) -> None:
        from datetime import datetime, timedelta, timezone
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM attack_chain_state WHERE occurred_at < ?", (cutoff,))

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
        """Asset profilini ekle ya da güncelle (INSERT OR REPLACE)."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO asset_baselines
                       (source_ip, tenant_id, first_seen_at, last_seen_at,
                        avg_events_per_hour, typical_ports, typical_destinations,
                        typical_event_actions, sample_hours, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(source_ip, tenant_id) DO UPDATE SET
                           last_seen_at          = excluded.last_seen_at,
                           avg_events_per_hour   = excluded.avg_events_per_hour,
                           typical_ports         = excluded.typical_ports,
                           typical_destinations  = excluded.typical_destinations,
                           typical_event_actions = excluded.typical_event_actions,
                           sample_hours          = excluded.sample_hours,
                           updated_at            = excluded.updated_at
                    """,
                    (
                        source_ip, tenant_id, first_seen_at, last_seen_at,
                        avg_events_per_hour,
                        json.dumps(typical_ports),
                        json.dumps(typical_destinations),
                        json.dumps(typical_event_actions),
                        sample_hours, now,
                    ),
                )

    def get_all_asset_baselines(self, tenant_id: str = "default") -> dict[str, dict]:
        """tenant_id'ye ait tüm asset profillerini dict[source_ip → dict] olarak döner."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM asset_baselines WHERE tenant_id = ?", (tenant_id,)
            ).fetchall()
        result = {}
        for r in rows:
            result[r["source_ip"]] = {
                "source_ip":             r["source_ip"],
                "tenant_id":             r["tenant_id"],
                "first_seen_at":         r["first_seen_at"],
                "last_seen_at":          r["last_seen_at"],
                "avg_events_per_hour":   r["avg_events_per_hour"],
                "typical_ports":         json.loads(r["typical_ports"] or "[]"),
                "typical_destinations":  json.loads(r["typical_destinations"] or "[]"),
                "typical_event_actions": json.loads(r["typical_event_actions"] or "[]"),
                "sample_hours":          r["sample_hours"],
                "updated_at":            r["updated_at"],
            }
        return result

    def get_asset_baseline(self, source_ip: str, tenant_id: str = "default") -> Optional[dict]:
        """Tek bir IP'nin profilini döner. Bulunamazsa None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM asset_baselines WHERE source_ip = ? AND tenant_id = ?",
                (source_ip, tenant_id),
            ).fetchone()
        if not row:
            return None
        return {
            "source_ip":             row["source_ip"],
            "tenant_id":             row["tenant_id"],
            "first_seen_at":         row["first_seen_at"],
            "last_seen_at":          row["last_seen_at"],
            "avg_events_per_hour":   row["avg_events_per_hour"],
            "typical_ports":         json.loads(row["typical_ports"] or "[]"),
            "typical_destinations":  json.loads(row["typical_destinations"] or "[]"),
            "typical_event_actions": json.loads(row["typical_event_actions"] or "[]"),
            "sample_hours":          row["sample_hours"],
            "updated_at":            row["updated_at"],
        }

    # ── False Positive Rules ──────────────────────────────────────────────────

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
                """
                INSERT INTO fp_rules (fp_rule_id, event_action, source_ip, destination_ip,
                    destination_port, observer_hostname, tenant_id, reason, created_by,
                    created_at, expires_at, is_active, hit_count)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,1,0)
                """,
                (fp_rule_id, event_action, source_ip, destination_ip,
                 destination_port, observer_hostname, tenant_id, reason,
                 created_by, created_at, expires_at),
            )

    def get_active_fp_rules(self, tenant_id: str = "default") -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM fp_rules WHERE tenant_id = ? AND is_active = 1 ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_fp_rules(self, tenant_id: str = "default") -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM fp_rules WHERE tenant_id = ? ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def deactivate_fp_rule(self, fp_rule_id: str, tenant_id: str = "default") -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE fp_rules SET is_active = 0 WHERE fp_rule_id = ? AND tenant_id = ?",
                (fp_rule_id, tenant_id),
            )
            return cur.rowcount > 0

    def increment_fp_hit(self, fp_rule_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE fp_rules SET hit_count = hit_count + 1 WHERE fp_rule_id = ?",
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
            expires_at = (
                datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
            ).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO blocked_ips
                       (block_id, ip, reason, blocked_by, blocked_at,
                        is_active, source_incident_id, provider, tenant_id, expires_at, offense_count)
                       VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)""",
                    (block_id, ip, reason, blocked_by,
                     datetime.now(timezone.utc).isoformat(),
                     source_incident_id, provider, tenant_id, expires_at, offense_count),
                )

    def unblock_ip(self, ip: str, unblocked_by: str, tenant_id: str = "default") -> bool:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """UPDATE blocked_ips
                       SET is_active=0, unblocked_at=?, unblocked_by=?
                       WHERE ip=? AND is_active=1 AND tenant_id=?""",
                    (datetime.now(timezone.utc).isoformat(), unblocked_by, ip, tenant_id),
                )
                return cur.rowcount > 0

    def get_blocked_ips(self, active_only: bool = True, tenant_id: Optional[str] = None) -> list[dict]:
        with self._connect() as conn:
            clauses = []
            params: list = []
            if active_only:
                clauses.append("is_active = 1")
            if tenant_id is not None:
                clauses.append("tenant_id = ?")
                params.append(tenant_id)
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = conn.execute(
                f"SELECT * FROM blocked_ips {where} ORDER BY blocked_at DESC",
                params,
            ).fetchall()
            return [dict(r) for r in rows]

    def get_block_by_ip(self, ip: str, tenant_id: str = "default") -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM blocked_ips WHERE ip=? AND is_active=1 AND tenant_id=? LIMIT 1",
                (ip, tenant_id),
            ).fetchone()
            return dict(row) if row else None

    def is_ip_blocked(self, ip: str, tenant_id: str = "default") -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM blocked_ips WHERE ip=? AND is_active=1 AND tenant_id=? LIMIT 1",
                (ip, tenant_id),
            ).fetchone()
            return row is not None

    def get_offense_count(self, ip: str, tenant_id: str = "default") -> int:
        """IP'nin tüm zamanlar bloklanma sayısını döndür (aktif + pasif)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM blocked_ips WHERE ip=? AND tenant_id=?",
                (ip, tenant_id),
            ).fetchone()
            return int(row["cnt"]) if row else 0

    def get_expired_blocks(self, tenant_id: Optional[str] = None) -> list[dict]:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            clauses = ["is_active = 1", "expires_at IS NOT NULL", "expires_at <= ?"]
            params: list = [now]
            if tenant_id is not None:
                clauses.append("tenant_id = ?")
                params.append(tenant_id)
            where = f"WHERE {' AND '.join(clauses)}"
            rows = conn.execute(
                f"SELECT * FROM blocked_ips {where}", params
            ).fetchall()
            return [dict(r) for r in rows]

    def get_correlated_events(
        self,
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list[CorrelatedEvent]:
        """Korelasyon olaylarını filtreli getir — en yeni önce."""
        clauses, params = [], []
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM correlated_events {where} ORDER BY created_at DESC LIMIT ?",
                params,
            ).fetchall()
        return [self._row_to_correlated_event(r) for r in rows]

    def get_correlated_event_by_id(self, corr_id: str) -> Optional["CorrelatedEvent"]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM correlated_events WHERE corr_id=?", (corr_id,)
            ).fetchone()
        return self._row_to_correlated_event(row) if row else None

    # Enricher'ın sorgulayabileceği kolon beyaz listesi — f-string injection'a karşı
    _VALID_LOG_GROUP_FIELDS: frozenset = frozenset({
        "source_ip", "destination_ip", "observer_hostname",
        "username", "device_id",
    })

    def get_related_logs_for_incident(
        self,
        source_ip: str,
        around_iso: str,
        window_minutes: int = 30,
        limit: int = 20,
        group_by_field: str = "source_ip",
    ) -> list["NormalizedLog"]:
        """
        group_value'ya ait ±window_minutes aralığındaki normalize logları döner.
        group_by_field: korelasyonun hangi kolonu kullandığını belirtir
        (source_ip | destination_ip | observer_hostname | username | device_id).
        Bilinmeyen değer → source_ip'e düşer.
        """
        if group_by_field not in self._VALID_LOG_GROUP_FIELDS:
            logger.warning("Geçersiz group_by_field: %r → source_ip kullanılıyor", group_by_field)
            group_by_field = "source_ip"
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM normalized_logs
                WHERE {group_by_field} = ?
                  AND datetime(timestamp) BETWEEN
                      datetime(?, ?)
                      AND datetime(?, ?)
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (
                    source_ip,
                    around_iso, f"-{window_minutes} minutes",
                    around_iso, f"+{window_minutes} minutes",
                    limit,
                ),
            ).fetchall()
        return [self._row_to_normalized_log(r) for r in rows]

    def _row_to_correlated_event(self, row: sqlite3.Row) -> CorrelatedEvent:
        def _split(val: str) -> list[str]:
            return [v for v in (val or "").split(",") if v]
        return CorrelatedEvent(
            corr_id           = row["corr_id"],
            rule_id           = row["rule_id"],
            rule_name         = row["rule_name"],
            event_action        = row["event_action"],
            severity          = row["severity"],
            group_value       = row["group_value"],
            matched_count     = row["matched_count"],
            window_seconds    = row["window_seconds"],
            first_seen        = datetime.fromisoformat(row["first_seen"]),
            last_seen         = datetime.fromisoformat(row["last_seen"]),
            message           = row["message"],
            created_at        = datetime.fromisoformat(row["created_at"]),
            mitre_techniques  = _split(row["mitre_techniques"] if "mitre_techniques" in row.keys() else ""),
            mitre_tactics     = _split(row["mitre_tactics"] if "mitre_tactics" in row.keys() else ""),
        )


    def count_correlated_events_since(self, hours: int = 24, tenant_id: Optional[str] = None) -> dict:
        """Son N saatteki korelasyon event sayısını döndür (toplam + kritik)."""
        clauses = ["created_at >= datetime('now', ?)"]
        params: list = [f"-{hours} hours"]
        if tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(tenant_id)
        where = "WHERE " + " AND ".join(clauses)
        with self._connect() as conn:
            row = conn.execute(
                f"""SELECT COUNT(*) AS total,
                    SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) AS high_plus
                    FROM correlated_events {where}""",
                params,
            ).fetchone()
        return {"total": row["total"] or 0, "high_plus": row["high_plus"] or 0}

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
        """Legacy snmp_devices tablosundan cihaz listesi döndür (SNMP route için)."""
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
        """
        Poll edilecek cihazları tüm SNMP v3 parametreleriyle döndür.
        Unified devices tablosundan okur; yoksa legacy snmp_devices'a döner.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT ip           AS host,
                          snmp_community AS community,
                          snmp_version,
                          snmp_v3_username,
                          snmp_v3_auth_protocol,
                          snmp_v3_auth_key,
                          snmp_v3_priv_protocol,
                          snmp_v3_priv_key,
                          name          AS label
                   FROM devices
                   WHERE snmp_community != '' AND status != 'offline'
                   ORDER BY rowid"""
            ).fetchall()
            if rows:
                return [dict(r) for r in rows]

            # Legacy fallback
            rows = conn.execute(
                "SELECT host, community, 'v2c' AS snmp_version, label FROM snmp_devices WHERE enabled=1 ORDER BY added_at"
            ).fetchall()
        return [dict(r) for r in rows]

    def remove_snmp_device(self, host: str) -> bool:
        """SNMP cihazını sil. Bulunursa True döner."""
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute("DELETE FROM snmp_devices WHERE host=?", (host,))
                return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    #  DEVICES (Unified Device Model)
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
        """Cihazı kaydet. Zaten varsa name, status ve last_seen güncelle."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO devices
                        (device_id, name, ip, mac, type, vendor, os_info,
                         status, first_seen, last_seen,
                         snmp_community, snmp_version,
                         snmp_v3_username, snmp_v3_auth_protocol,
                         snmp_v3_auth_key, snmp_v3_priv_protocol, snmp_v3_priv_key,
                         segment, notes, tenant_id)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(device_id) DO UPDATE SET
                        name                 = excluded.name,
                        ip                   = COALESCE(NULLIF(excluded.ip,''), ip),
                        status               = excluded.status,
                        last_seen            = excluded.last_seen,
                        os_info              = COALESCE(NULLIF(excluded.os_info,''), os_info),
                        vendor               = COALESCE(NULLIF(excluded.vendor,''), vendor),
                        snmp_community       = COALESCE(NULLIF(excluded.snmp_community,''), snmp_community),
                        snmp_version         = COALESCE(NULLIF(excluded.snmp_version,''), snmp_version),
                        snmp_v3_username     = COALESCE(NULLIF(excluded.snmp_v3_username,''), snmp_v3_username),
                        snmp_v3_auth_protocol= COALESCE(NULLIF(excluded.snmp_v3_auth_protocol,''), snmp_v3_auth_protocol),
                        snmp_v3_auth_key     = COALESCE(NULLIF(excluded.snmp_v3_auth_key,''), snmp_v3_auth_key),
                        snmp_v3_priv_protocol= COALESCE(NULLIF(excluded.snmp_v3_priv_protocol,''), snmp_v3_priv_protocol),
                        snmp_v3_priv_key     = COALESCE(NULLIF(excluded.snmp_v3_priv_key,''), snmp_v3_priv_key)
                    """,
                    (device_id, name, ip, mac, device_type, vendor, os_info,
                     status, now, now,
                     snmp_community, snmp_version,
                     snmp_v3_username, snmp_v3_auth_protocol,
                     snmp_v3_auth_key, snmp_v3_priv_protocol, snmp_v3_priv_key,
                     segment, notes, tenant_id),
                )

    def update_device_status(self, device_id: str, status: str) -> None:
        """Cihaz durumunu güncelle (up/down/unknown)."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE devices SET status=?, last_seen=? WHERE device_id=?",
                    (status, now, device_id),
                )

    def get_devices(
        self,
        device_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> list[dict]:
        """Tüm cihazları listele. device_type ve/veya tenant_id ile filtrele."""
        clauses, params = [], []
        if device_type:
            clauses.append("type=?")
            params.append(device_type)
        if tenant_id is not None:
            clauses.append("tenant_id=?")
            params.append(tenant_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM devices {where} ORDER BY type, name", params
            ).fetchall()
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
        """Cihazın SNMP ayarlarını güncelle. Cihaz bulunamazsa False döner."""
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """UPDATE devices
                       SET snmp_community=?, snmp_version=?,
                           snmp_v3_username=?, snmp_v3_auth_protocol=?,
                           snmp_v3_auth_key=?, snmp_v3_priv_protocol=?,
                           snmp_v3_priv_key=?
                       WHERE device_id=?""",
                    (community, version, v3_username, v3_auth_protocol,
                     v3_auth_key, v3_priv_protocol, v3_priv_key, device_id),
                )
                return cur.rowcount > 0

    def get_device(self, device_id: str) -> Optional[dict]:
        """Tek bir cihazı döndür."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()
            return dict(row) if row else None

    def remove_device(self, device_id: str) -> bool:
        """Cihazı sil. Bulunursa True döner."""
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "DELETE FROM devices WHERE device_id=?", (device_id,)
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    #  SNMP POLL HISTORY (bandwidth delta için)
    # ------------------------------------------------------------------ #

    def upsert_snmp_poll(
        self, host: str, if_index: str, if_name: str,
        hc_in: int, hc_out: int,
    ) -> None:
        """Son poll değerlerini kaydet (REPLACE — sadece son değer tutulur)."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO snmp_poll_history
                        (host, if_index, if_name, polled_at, hc_in, hc_out)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (host, if_index, if_name, now, hc_in, hc_out),
                )

    def get_snmp_poll(self, host: str, if_index: str) -> Optional[dict]:
        """Son poll verisini döndür."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM snmp_poll_history WHERE host=? AND if_index=?",
                (host, if_index),
            ).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------ #
    #  SERVICE CHECKS (uptime checker sonuçları)
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
        """Uptime/servis kontrol sonucunu kaydet."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO service_checks
                        (device_id, check_type, target, port,
                         status, rtt_ms, checked_at, details)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (device_id, check_type, target, port,
                     status, rtt_ms, now, details),
                )

    def get_service_checks(
        self,
        device_id: Optional[str] = None,
        check_type: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Servis kontrol geçmişini listele."""
        conditions, params = [], []
        if device_id:
            conditions.append("device_id=?")
            params.append(device_id)
        if check_type:
            conditions.append("check_type=?")
            params.append(check_type)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM service_checks {where} ORDER BY checked_at DESC LIMIT ?",
                params,
            ).fetchall()
            return [dict(r) for r in rows]

    def _migrate_snmpv3_columns(self) -> None:
        """SNMPv3 credential kolonlarını devices tablosuna ekle (idempotent)."""
        v3_columns = [
            ("snmp_v3_username",      "TEXT DEFAULT ''"),
            ("snmp_v3_auth_protocol", "TEXT DEFAULT 'SHA'"),
            ("snmp_v3_auth_key",      "TEXT DEFAULT ''"),
            ("snmp_v3_priv_protocol", "TEXT DEFAULT 'AES'"),
            ("snmp_v3_priv_key",      "TEXT DEFAULT ''"),
        ]
        with self._lock:
            with self._connect() as conn:
                existing = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
                for col_name, col_def in v3_columns:
                    if col_name not in existing:
                        conn.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_def}")

    def _migrate_snmp_to_devices(self) -> None:
        """Mevcut snmp_devices kayıtlarını devices tablosuna taşı."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute("SELECT * FROM snmp_devices").fetchall()
                for row in rows:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO devices
                            (device_id, name, ip, type, snmp_community,
                             status, first_seen, last_seen)
                        VALUES (?,?,?,?,?,?,?,?)
                        """,
                        (
                            row["host"],
                            row["label"] if row["label"] else row["host"],
                            row["host"],
                            "snmp",
                            row["community"],
                            "unknown",
                            row["added_at"],
                            now,
                        ),
                    )
        if rows:
            logger.info(f"{len(rows)} SNMP cihazı devices tablosuna migrate edildi")

    def _migrate_api_keys_to_hashed(self) -> None:
        """Plaintext API key'leri sil — hash olmayan kayıtlar geçersizdir."""
        import re
        sha256_pattern = re.compile(r'^[0-9a-f]{64}$')
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute("SELECT agent_id, api_key FROM api_keys").fetchall()
                stale = [row["agent_id"] for row in rows if not sha256_pattern.match(row["api_key"])]
                for agent_id in stale:
                    conn.execute("DELETE FROM api_keys WHERE agent_id=?", (agent_id,))
        if stale:
            logger.warning(f"Plaintext API key'ler silindi (agent'lar yeniden kayıt yaptırmalı): {stale}")

    def _migrate_raw_logs_parse_status(self) -> None:
        """raw_logs tablosunu normalized INTEGER → parse_status TEXT'e migrate et."""
        with self._connect() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(raw_logs)").fetchall()}
            if "parse_status" not in cols:
                conn.execute("ALTER TABLE raw_logs ADD COLUMN parse_status TEXT NOT NULL DEFAULT 'pending'")
                if "normalized" in cols:
                    conn.execute("""
                        UPDATE raw_logs SET parse_status = CASE
                            WHEN normalized = 1  THEN 'success'
                            WHEN normalized = -1 THEN 'failed'
                            ELSE 'pending'
                        END
                    """)
                conn.execute("DROP INDEX IF EXISTS idx_raw_normalized")
                logger.info("raw_logs: 'parse_status' kolonu eklendi, mevcut veriler migrate edildi")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_parse_status ON raw_logs(parse_status)")

    def _migrate_normalized_logs_columns(self) -> None:
        """normalized_logs tablosuna eksik kolonları ekle ve NULL tenant_id'leri düzelt."""
        with self._connect() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(normalized_logs)").fetchall()}
            if "extra" not in cols:
                conn.execute("ALTER TABLE normalized_logs ADD COLUMN extra TEXT NOT NULL DEFAULT '{}'")
                logger.info("normalized_logs: 'extra' kolonu eklendi")
            if "network_bytes" not in cols:
                conn.execute("ALTER TABLE normalized_logs ADD COLUMN network_bytes INTEGER")
                logger.info("normalized_logs: 'network_bytes' kolonu eklendi")
            if "tenant_id" in cols:
                result = conn.execute(
                    "UPDATE normalized_logs SET tenant_id='default' WHERE tenant_id IS NULL"
                )
                if result.rowcount:
                    logger.info(f"normalized_logs: {result.rowcount} kayıt tenant_id='default' olarak güncellendi")

    def _migrate_ecs_field_rename(self) -> None:
        """ECS-aligned field rename: mevcut DB kolonlarını yeni isimlere taşır (SQLite RENAME COLUMN)."""
        _normalized_renames = [
            ("source_host", "observer_hostname"),
            ("category",    "event_category"),
            ("event_type",  "event_action"),
            ("src_ip",      "source_ip"),
            ("dst_ip",      "destination_ip"),
            ("src_port",    "source_port"),
            ("dst_port",    "destination_port"),
            ("protocol",    "network_protocol"),
        ]
        _raw_renames      = [("source_host", "observer_hostname")]
        _corr_renames     = [("event_type", "event_action")]
        _sec_renames      = [("event_type", "event_action")]
        _inc_ev_renames   = [("event_type", "event_action")]
        _chain_renames    = [("src_ip", "source_ip")]

        def _rename_cols(conn, table: str, renames: list[tuple[str, str]]) -> None:
            cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for old, new in renames:
                if old in cols and new not in cols:
                    conn.execute(f"ALTER TABLE {table} RENAME COLUMN {old} TO {new}")
                    logger.info(f"{table}: '{old}' → '{new}' yeniden adlandırıldı")

        with self._connect() as conn:
            _rename_cols(conn, "normalized_logs",    _normalized_renames)
            _rename_cols(conn, "raw_logs",            _raw_renames)
            _rename_cols(conn, "correlated_events",   _corr_renames)
            _rename_cols(conn, "security_events",     _sec_renames)
            _rename_cols(conn, "incident_events",     _inc_ev_renames)
            _rename_cols(conn, "attack_chain_state",  _chain_renames)

            fts_cols = {
                row[1]
                for row in conn.execute("PRAGMA table_info(normalized_logs_fts)").fetchall()
            }
            if fts_cols and "src_ip" in fts_cols:
                conn.executescript("""
                    DROP TRIGGER IF EXISTS fts_insert;
                    DROP TRIGGER IF EXISTS fts_delete;
                    DROP TABLE  IF EXISTS normalized_logs_fts;
                """)
                logger.info("FTS5 tablosu yeniden oluşturmak için silindi")

    def _migrate_incidents_columns(self) -> None:
        """incidents tablosuna rule_id ve group_value kolonlarını ekle."""
        with self._connect() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}
            if "rule_id" not in cols:
                conn.execute("ALTER TABLE incidents ADD COLUMN rule_id TEXT")
                logger.info("incidents: 'rule_id' kolonu eklendi")
            if "group_value" not in cols:
                conn.execute("ALTER TABLE incidents ADD COLUMN group_value TEXT")
                logger.info("incidents: 'group_value' kolonu eklendi")

    def _migrate_correlated_events_mitre(self) -> None:
        """correlated_events tablosuna mitre_techniques ve mitre_tactics kolonlarını ekle."""
        with self._connect() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(correlated_events)").fetchall()}
            if "mitre_techniques" not in cols:
                conn.execute("ALTER TABLE correlated_events ADD COLUMN mitre_techniques TEXT DEFAULT ''")
                logger.info("correlated_events: 'mitre_techniques' kolonu eklendi")
            if "mitre_tactics" not in cols:
                conn.execute("ALTER TABLE correlated_events ADD COLUMN mitre_tactics TEXT DEFAULT ''")
                logger.info("correlated_events: 'mitre_tactics' kolonu eklendi")

    def _migrate_tenant_id(self) -> None:
        """Tüm data tablolarına tenant_id kolonu ekle (idempotent)."""
        tables = [
            "devices", "normalized_logs", "incidents",
            "alerts", "security_events", "correlated_events",
        ]
        with self._lock:
            with self._connect() as conn:
                for table in tables:
                    cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
                    if "tenant_id" not in cols:
                        conn.execute(
                            f"ALTER TABLE {table} ADD COLUMN tenant_id TEXT DEFAULT 'default'"
                        )
                        logger.info(f"{table}: 'tenant_id' kolonu eklendi")

    def _migrate_dns_hostname_columns(self) -> None:
        """normalized_logs tablosuna source_hostname ve destination_hostname kolonlarını ekle."""
        with self._lock:
            with self._connect() as conn:
                cols = {row[1] for row in conn.execute("PRAGMA table_info(normalized_logs)").fetchall()}
                if "source_hostname" not in cols:
                    conn.execute("ALTER TABLE normalized_logs ADD COLUMN source_hostname TEXT")
                    logger.info("normalized_logs: 'source_hostname' kolonu eklendi")
                if "destination_hostname" not in cols:
                    conn.execute("ALTER TABLE normalized_logs ADD COLUMN destination_hostname TEXT")
                    logger.info("normalized_logs: 'destination_hostname' kolonu eklendi")

    def _migrate_incident_v1_4_columns(self) -> None:
        """incidents tablosuna priority_score, closure_note, acknowledged_at, group_by_field kolonlarını ekle."""
        with self._lock:
            with self._connect() as conn:
                cols = {row[1] for row in conn.execute("PRAGMA table_info(incidents)").fetchall()}
                if "priority_score" not in cols:
                    conn.execute("ALTER TABLE incidents ADD COLUMN priority_score INTEGER DEFAULT 0")
                    logger.info("incidents: 'priority_score' kolonu eklendi")
                if "closure_note" not in cols:
                    conn.execute("ALTER TABLE incidents ADD COLUMN closure_note TEXT DEFAULT ''")
                    logger.info("incidents: 'closure_note' kolonu eklendi")
                if "acknowledged_at" not in cols:
                    conn.execute("ALTER TABLE incidents ADD COLUMN acknowledged_at TEXT")
                    logger.info("incidents: 'acknowledged_at' kolonu eklendi")
                if "group_by_field" not in cols:
                    conn.execute("ALTER TABLE incidents ADD COLUMN group_by_field TEXT DEFAULT 'source_ip'")
                    logger.info("incidents: 'group_by_field' kolonu eklendi")

    def _migrate_blocked_ips_expires_at(self) -> None:
        """blocked_ips tablosuna expires_at kolonu ve index'i ekle."""
        with self._lock:
            with self._connect() as conn:
                cols = {row[1] for row in conn.execute("PRAGMA table_info(blocked_ips)").fetchall()}
                if "expires_at" not in cols:
                    conn.execute("ALTER TABLE blocked_ips ADD COLUMN expires_at TEXT")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_blocked_expires ON blocked_ips(expires_at)")
                    logger.info("blocked_ips: 'expires_at' kolonu ve index eklendi")

    def _migrate_blocked_ips_offense_count(self) -> None:
        """blocked_ips tablosuna offense_count kolonu ekle."""
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute("ALTER TABLE blocked_ips ADD COLUMN offense_count INTEGER NOT NULL DEFAULT 1")
                    logger.info("blocked_ips: 'offense_count' kolonu eklendi")
                except Exception:
                    pass

    def _migrate_db_users_totp_columns(self) -> None:
        """db_users tablosuna TOTP kolonları ekle."""
        with self._lock:
            with self._connect() as conn:
                cols = [r[1] for r in conn.execute("PRAGMA table_info(db_users)").fetchall()]
                if "totp_secret" not in cols:
                    conn.execute("ALTER TABLE db_users ADD COLUMN totp_secret TEXT")
                    logger.info("db_users: 'totp_secret' kolonu eklendi")
                if "totp_enabled" not in cols:
                    conn.execute("ALTER TABLE db_users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
                    logger.info("db_users: 'totp_enabled' kolonu eklendi")

    # ------------------------------------------------------------------ #
    #  TENANTS
    # ------------------------------------------------------------------ #

    def ensure_default_tenant(self) -> None:
        """Default tenant yoksa oluştur."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO tenants (id, name, created_at) VALUES (?,?,?)",
                ("default", "Default", now),
            )

    def create_tenant(self, id: str, name: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute(
                        "INSERT INTO tenants (id, name, created_at) VALUES (?,?,?)",
                        (id, name, now),
                    )
                    return True
                except sqlite3.IntegrityError:
                    return False

    def get_tenants(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM tenants ORDER BY name").fetchall()
            return [dict(r) for r in rows]

    def get_tenant(self, id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tenants WHERE id=?", (id,)).fetchone()
            return dict(row) if row else None

    def update_tenant(self, id: str, name: Optional[str] = None, is_active: Optional[int] = None) -> bool:
        fields, params = [], []
        if name is not None:
            fields.append("name=?")
            params.append(name)
        if is_active is not None:
            fields.append("is_active=?")
            params.append(is_active)
        if not fields:
            return False
        params.append(id)
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(f"UPDATE tenants SET {','.join(fields)} WHERE id=?", params)
                return cur.rowcount > 0

    def delete_tenant(self, id: str) -> bool:
        if id == "default":
            return False
        with self._lock:
            with self._connect() as conn:
                if not conn.execute("SELECT 1 FROM tenants WHERE id=?", (id,)).fetchone():
                    return False
                conn.execute("DELETE FROM sites WHERE tenant_id=?", (id,))
                conn.execute("DELETE FROM db_users WHERE tenant_id=?", (id,))
                conn.execute("DELETE FROM tenants WHERE id=?", (id,))
                return True

    # ------------------------------------------------------------------ #
    #  SITES
    # ------------------------------------------------------------------ #

    def create_site(self, id: str, tenant_id: str, name: str, location: str = "", tz: str = "UTC") -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute(
                        "INSERT INTO sites (id, tenant_id, name, location, tz, created_at) VALUES (?,?,?,?,?,?)",
                        (id, tenant_id, name, location, tz, now),
                    )
                    return True
                except sqlite3.IntegrityError:
                    return False

    def get_sites(self, tenant_id: Optional[str] = None) -> list[dict]:
        with self._connect() as conn:
            if tenant_id:
                rows = conn.execute(
                    "SELECT * FROM sites WHERE tenant_id=? ORDER BY name", (tenant_id,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM sites ORDER BY tenant_id, name").fetchall()
            return [dict(r) for r in rows]

    def get_site(self, id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM sites WHERE id=?", (id,)).fetchone()
            return dict(row) if row else None

    def delete_site(self, id: str) -> bool:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute("DELETE FROM sites WHERE id=?", (id,))
                return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    #  DB USERS  (in-memory _USERS'a ek olarak DB'deki kullanıcılar)
    # ------------------------------------------------------------------ #

    def create_db_user(self, username: str, password_hash: str, role: str, tenant_id: Optional[str]) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                try:
                    conn.execute(
                        "INSERT INTO db_users (username, password_hash, role, tenant_id, created_at) VALUES (?,?,?,?,?)",
                        (username, password_hash, role, tenant_id, now),
                    )
                    return True
                except sqlite3.IntegrityError:
                    return False

    def get_db_user(self, username: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM db_users WHERE username=?", (username,)).fetchone()
            return dict(row) if row else None

    def get_db_users(self, tenant_id: Optional[str] = None) -> list[dict]:
        with self._connect() as conn:
            if tenant_id is not None:
                rows = conn.execute(
                    "SELECT username, role, tenant_id, created_at FROM db_users WHERE tenant_id=? ORDER BY username",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT username, role, tenant_id, created_at FROM db_users ORDER BY tenant_id, username"
                ).fetchall()
            return [dict(r) for r in rows]

    def delete_db_user(self, username: str) -> bool:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute("DELETE FROM db_users WHERE username=?", (username,))
                return cur.rowcount > 0

    def update_db_user_password(self, username: str, password_hash: str) -> bool:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE db_users SET password_hash=? WHERE username=?", (password_hash, username)
                )
                return cur.rowcount > 0

    def update_db_user_role(self, username: str, role: str) -> bool:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "UPDATE db_users SET role=? WHERE username=?", (role, username)
                )
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
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO db_users (username, password_hash, role, tenant_id)"
                    " VALUES (%s, '__TOTP_ONLY__', %s, %s)",
                    (username, role, tenant_id),
                )
                conn.execute(
                    "UPDATE db_users SET totp_secret=%s, totp_enabled=0 WHERE username=%s",
                    (encrypt(secret), username),
                )

    def enable_user_totp(self, username: str) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE db_users SET totp_enabled=1 WHERE username=%s",
                    (username,),
                )

    def disable_user_totp(self, username: str) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE db_users SET totp_enabled=0, totp_secret=NULL WHERE username=%s",
                    (username,),
                )

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
        """Tüm agent_id → key_hash eşlemesini döndür."""
        with self._connect() as conn:
            rows = conn.execute("SELECT agent_id, api_key FROM api_keys").fetchall()
            return {row["agent_id"]: row["api_key"] for row in rows}

    def delete_api_key(self, agent_id: str) -> None:
        """Agent API key'ini sil."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM api_keys WHERE agent_id=?", (agent_id,))

    # ------------------------------------------------------------------ #
    #  AUDIT LOG
    # ------------------------------------------------------------------ #

    def save_audit_event(
        self,
        actor: str,
        action: str,
        resource: str,
        detail: str = "",
        ip_address: str = "",
    ) -> None:
        import hashlib
        import uuid as _uuid
        event_id = str(_uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT entry_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1"
                ).fetchone()
                previous_hash = row[0] if row else _AUDIT_CHAIN_GENESIS
                content = _audit_content(event_id, actor, action, resource, detail or "", ip_address or "", now, previous_hash)
                entry_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                conn.execute(
                    "INSERT INTO audit_log "
                    "(event_id, actor, action, resource, detail, ip_address, timestamp, previous_hash, entry_hash) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (event_id, actor, action, resource, detail, ip_address, now, previous_hash, entry_hash),
                )

    def get_audit_log(self, limit: int = 100, actor: str = "") -> list[dict]:
        with self._connect() as conn:
            if actor:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE actor=? ORDER BY timestamp DESC LIMIT ?",
                    (actor, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
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
            content = _audit_content(
                row["event_id"], row["actor"], row["action"], row["resource"],
                row["detail"] or "", row["ip_address"] or "", ts, previous_hash,
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

    def _migrate_audit_hash_columns(self) -> None:
        with self._connect() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
            if "previous_hash" not in cols:
                conn.execute("ALTER TABLE audit_log ADD COLUMN previous_hash TEXT")
            if "entry_hash" not in cols:
                conn.execute("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_entry_hash ON audit_log(entry_hash)"
            )

    # ------------------------------------------------------------------ #
    #  TOKEN BLACKLIST
    # ------------------------------------------------------------------ #

    def blacklist_token(self, jti: str, expires_at: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO token_blacklist (jti, expires_at) VALUES (?,?)",
                (jti, expires_at),
            )

    def is_token_blacklisted(self, jti: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM token_blacklist WHERE jti=?", (jti,)
            ).fetchone()
        return row is not None

    def cleanup_expired_blacklist(self) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM token_blacklist WHERE expires_at < ?", (now,)
            )
        return cur.rowcount

    # ------------------------------------------------------------------ #
    #  THREAT INTEL CACHE
    # ------------------------------------------------------------------ #

    def get_threat_intel(self, ip: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM threat_intel_cache WHERE ip=?", (ip,)
            ).fetchone()
        return dict(row) if row else None

    def save_threat_intel(self, ip: str, score: int, total_reports: int,
                          country_code: str, isp: str,
                          feodo_listed: bool = False, feodo_malware: str = "",
                          threatfox_score: int = 0, threatfox_malware: str = "",
                          greynoise_noise: bool = False, greynoise_riot: bool = False,
                          greynoise_classification: str = "",
                          composite_score: int = 0) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO threat_intel_cache
                     (ip, score, total_reports, country_code, isp,
                      feodo_listed, feodo_malware,
                      threatfox_score, threatfox_malware,
                      greynoise_noise, greynoise_riot, greynoise_classification,
                      composite_score, queried_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ip) DO UPDATE SET
                     score=excluded.score,
                     total_reports=excluded.total_reports,
                     country_code=excluded.country_code,
                     isp=excluded.isp,
                     feodo_listed=excluded.feodo_listed,
                     feodo_malware=excluded.feodo_malware,
                     threatfox_score=excluded.threatfox_score,
                     threatfox_malware=excluded.threatfox_malware,
                     greynoise_noise=excluded.greynoise_noise,
                     greynoise_riot=excluded.greynoise_riot,
                     greynoise_classification=excluded.greynoise_classification,
                     composite_score=excluded.composite_score,
                     queried_at=excluded.queried_at""",
                (ip, score, total_reports, country_code, isp,
                 int(feodo_listed), feodo_malware,
                 threatfox_score, threatfox_malware,
                 int(greynoise_noise), int(greynoise_riot), greynoise_classification,
                 composite_score, now),
            )

    # ------------------------------------------------------------------ #
    #  TOPOLOGY
    # ------------------------------------------------------------------ #

    def upsert_topology_node(
        self,
        device_id: str,
        name: str,
        ip: str = "",
        device_type: str = "unknown",
        vendor: str = "",
        os_info: str = "",
        layer: int = 3,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO topology_nodes
                        (device_id, name, ip, type, vendor, os_info, layer, updated_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    ON CONFLICT(device_id) DO UPDATE SET
                        name=excluded.name, ip=excluded.ip, type=excluded.type,
                        vendor=excluded.vendor, os_info=excluded.os_info,
                        layer=excluded.layer, updated_at=excluded.updated_at
                    """,
                    (device_id, name, ip, device_type, vendor, os_info, layer, now),
                )

    def upsert_topology_edge(
        self,
        src_id: str,
        dst_id: str,
        link_type: str = "ip",
        discovered: str = "arp",
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        canonical_src, canonical_dst = sorted([src_id, dst_id])
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO topology_edges (src_id, dst_id, link_type, discovered, updated_at)
                    VALUES (?,?,?,?,?)
                    ON CONFLICT(src_id, dst_id, link_type) DO UPDATE SET
                        discovered=excluded.discovered, updated_at=excluded.updated_at
                    """,
                    (canonical_src, canonical_dst, link_type, discovered, now),
                )

    def get_topology_graph(self) -> dict:
        """Tüm node ve edge'leri döndür."""
        with self._connect() as conn:
            nodes = [dict(r) for r in conn.execute("SELECT * FROM topology_nodes").fetchall()]
            edges = [dict(r) for r in conn.execute("SELECT * FROM topology_edges").fetchall()]
        return {"nodes": nodes, "edges": edges}

    def clear_topology(self) -> None:
        """Topoloji tablolarını temizle (rebuild öncesi)."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM topology_edges")
                conn.execute("DELETE FROM topology_nodes")


    # ------------------------------------------------------------------ #
    #  INCIDENTS
    # ------------------------------------------------------------------ #

    def create_incident(self, incident: "Incident", tenant_id: str = "default") -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO incidents
                       (incident_id, title, description, severity, status,
                        assigned_to, source_event_id, source_type,
                        created_by, notes, rule_id, group_value, group_by_field,
                        priority_score, closure_note,
                        created_at, updated_at, resolved_at, acknowledged_at, tenant_id)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        incident.incident_id, incident.title, incident.description,
                        incident.severity, incident.status.value,
                        incident.assigned_to, incident.source_event_id, incident.source_type,
                        incident.created_by, incident.notes,
                        incident.rule_id, incident.group_value, incident.group_by_field,
                        incident.priority_score, incident.closure_note,
                        now, now, None, None, tenant_id,
                    ),
                )

    def find_open_incident_for_rule(self, rule_id: str, group_value: str) -> Optional[str]:
        with self._connect() as conn:
            row = conn.execute(
                """SELECT incident_id FROM incidents
                   WHERE rule_id=? AND group_value=? AND status IN ('open','investigating')
                   ORDER BY created_at DESC LIMIT 1""",
                (rule_id, group_value),
            ).fetchone()
            return row["incident_id"] if row else None

    _SEV_ORDER = {"info": 1, "warning": 2, "critical": 3}

    def escalate_incident_severity(self, incident_id: str, new_severity: str) -> bool:
        row = self.get_incident(incident_id)
        if not row:
            return False
        current = self._SEV_ORDER.get(row["severity"], 0)
        incoming = self._SEV_ORDER.get(new_severity, 0)
        if incoming <= current:
            return False
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE incidents SET severity=?, updated_at=? WHERE incident_id=?",
                    (new_severity, now, incident_id),
                )
        return True

    def add_incident_event(
        self,
        incident_id: str,
        event_id: str,
        event_action: str,
        severity: str,
        message: str,
        occurred_at: str,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO incident_events
                       (incident_id, event_id, event_action, severity, message, occurred_at, added_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    (incident_id, event_id, event_action, severity, message, occurred_at, now),
                )

    def get_incident_events(self, incident_id: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incident_events WHERE incident_id=? ORDER BY occurred_at ASC",
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
        query = "SELECT * FROM incidents WHERE 1=1"
        params: list = []
        if status:
            query += " AND status=?"
            params.append(status)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if assigned_to:
            query += " AND assigned_to=?"
            params.append(assigned_to)
        if tenant_id is not None:
            query += " AND tenant_id=?"
            params.append(tenant_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_incident(self, incident_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()
            return dict(row) if row else None

    def resolve_all_incidents(self, tenant_id: Optional[str] = None) -> int:
        """Açık ve inceleniyor durumdaki tüm incident'ları resolved yapar. Kaç tane güncellendi döner."""
        now = datetime.now(timezone.utc).isoformat()
        clause = "WHERE status IN ('open','investigating')"
        params: list = [now, now, "Toplu çözümleme"]
        if tenant_id is not None:
            clause += " AND tenant_id=?"
            params.append(tenant_id)
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    f"UPDATE incidents SET status='resolved', resolved_at=?, updated_at=?, closure_note=? {clause}",
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
        now = datetime.now(timezone.utc).isoformat()
        if status is not None:
            fields.append("status=?")
            params.append(status)
            if status == "resolved":
                fields.append("resolved_at=?")
                params.append(now)
            if status == "investigating":
                # COALESCE: acknowledged_at NULL ise set et, dolu ise dokunma (tek sorgu)
                fields.append("acknowledged_at=COALESCE(acknowledged_at,?)")
                params.append(now)
        if assigned_to is not None:
            fields.append("assigned_to=?")
            params.append(assigned_to)
        if notes is not None:
            fields.append("notes=?")
            params.append(notes)
        if title is not None:
            fields.append("title=?")
            params.append(title)
        if description is not None:
            fields.append("description=?")
            params.append(description)
        if closure_note is not None:
            fields.append("closure_note=?")
            params.append(closure_note)
        if priority_score is not None:
            fields.append("priority_score=?")
            params.append(priority_score)
        if not fields:
            return False
        fields.append("updated_at=?")
        params.append(now)
        params.append(incident_id)
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    f"UPDATE incidents SET {', '.join(fields)} WHERE incident_id=?",
                    params,
                )
                return cur.rowcount > 0

    def delete_incident(self, incident_id: str) -> bool:
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "DELETE FROM incidents WHERE incident_id=?", (incident_id,)
                )
                return cur.rowcount > 0

    def count_incidents(self, status: Optional[str] = None, tenant_id: Optional[str] = None) -> int:
        clauses, params = [], []
        if status:
            clauses.append("status=?")
            params.append(status)
        if tenant_id is not None:
            clauses.append("tenant_id=?")
            params.append(tenant_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as conn:
            return conn.execute(f"SELECT COUNT(*) FROM incidents {where}", params).fetchone()[0]


# Global instance — uygulama boyunca tek bir tane
import os as _os
_DATABASE_URL = _os.getenv("DATABASE_URL")
if _DATABASE_URL:
    from server.database_pg import DatabaseManager as _PgManager
    db: DatabaseManager = _PgManager(_DATABASE_URL)
else:
    db = DatabaseManager()
