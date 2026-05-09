"""
NetGuard — Network Intelligence API

GET /api/v1/network/intelligence — Zeek zenginleştirme özetini döner:
  - Zeek kaynak türlerine göre olay sayıları (24s)
  - JA3 şüpheli parmak izi tespitleri
  - SSL/x509 sertifika anomalileri
  - FTP hassas komutlar
  - SMTP toplu gönderim
  - DNS sorgulama istatistikleri
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends

from server.auth import User, get_current_user, tenant_scope
from server.database import db

logger = logging.getLogger(__name__)
router = APIRouter()


def _query(sql: str, params: list, tenant_id: str) -> list:
    """Güvenli tenant_id filtreli ham DB sorgusu."""
    import sqlite3
    import os

    _IS_PG = bool(os.getenv("DATABASE_URL"))
    if _IS_PG:
        import psycopg
        conn_str = os.environ["DATABASE_URL"]
        with psycopg.connect(conn_str) as conn:
            rows = conn.execute(sql.replace("?", "%s"), params).fetchall()
            cols = [d[0] for d in conn.execute(sql.replace("?", "%s"), params).description]
            return [dict(zip(cols, row)) for row in rows]

    db_path = os.getenv("NETGUARD_DB_PATH", "netguard.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


@router.get("/network/intelligence")
def network_intelligence(
    hours: int = 24,
    current_user: User = Depends(get_current_user),
):
    """
    Zeek tabanlı network intelligence özeti.
    Faz 1 zenginleştirme verilerini (JA3, x509, SMTP, FTP) yüzeye çıkarır.
    """
    if hours < 1 or hours > 168:
        hours = 24

    tenant_id = tenant_scope(current_user)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    with db._connect() as conn:

        # ── Zeek event_action dağılımı ────────────────────────────────────
        zeek_distribution = {}
        rows = conn.execute(
            """
            SELECT event_action, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE source_type = 'zeek'
              AND timestamp >= ?
              AND tenant_id = ?
            GROUP BY event_action
            ORDER BY cnt DESC
            LIMIT 20
            """,
            [since, tenant_id],
        ).fetchall()
        for r in rows:
            zeek_distribution[r["event_action"]] = r["cnt"]

        # ── JA3 şüpheli parmak izleri ─────────────────────────────────────
        ja3_suspicious = []
        rows = conn.execute(
            """
            SELECT source_ip, destination_ip, message, timestamp
            FROM normalized_logs
            WHERE event_action = 'tls_suspicious_fingerprint'
              AND timestamp >= ?
              AND tenant_id = ?
            ORDER BY timestamp DESC
            LIMIT 50
            """,
            [since, tenant_id],
        ).fetchall()
        for r in rows:
            ja3_suspicious.append({
                "source_ip":      r["source_ip"],
                "destination_ip": r["destination_ip"],
                "message":        r["message"],
                "timestamp":      r["timestamp"],
            })

        # ── SSL sertifika anomalileri (self-signed + invalid) ──────────────
        ssl_anomalies = []
        rows = conn.execute(
            """
            SELECT source_ip, destination_ip, message, severity, timestamp
            FROM normalized_logs
            WHERE event_action = 'ssl_connection'
              AND severity = 'warning'
              AND timestamp >= ?
              AND tenant_id = ?
            ORDER BY timestamp DESC
            LIMIT 50
            """,
            [since, tenant_id],
        ).fetchall()
        for r in rows:
            ssl_anomalies.append({
                "source_ip":      r["source_ip"],
                "destination_ip": r["destination_ip"],
                "message":        r["message"],
                "severity":       r["severity"],
                "timestamp":      r["timestamp"],
            })

        # ── x509 self-signed sertifikalar ─────────────────────────────────
        self_signed_certs = []
        rows = conn.execute(
            """
            SELECT source_ip, message, timestamp
            FROM normalized_logs
            WHERE event_action = 'x509_certificate'
              AND severity = 'warning'
              AND timestamp >= ?
              AND tenant_id = ?
            ORDER BY timestamp DESC
            LIMIT 30
            """,
            [since, tenant_id],
        ).fetchall()
        for r in rows:
            self_signed_certs.append({
                "source_ip": r["source_ip"],
                "message":   r["message"],
                "timestamp": r["timestamp"],
            })

        # ── FTP hassas komutlar (RETR/STOR/DELE) ──────────────────────────
        ftp_sensitive = []
        rows = conn.execute(
            """
            SELECT source_ip, destination_ip, message, timestamp
            FROM normalized_logs
            WHERE event_action = 'ftp_command'
              AND severity = 'warning'
              AND timestamp >= ?
              AND tenant_id = ?
            ORDER BY timestamp DESC
            LIMIT 30
            """,
            [since, tenant_id],
        ).fetchall()
        for r in rows:
            ftp_sensitive.append({
                "source_ip":      r["source_ip"],
                "destination_ip": r["destination_ip"],
                "message":        r["message"],
                "timestamp":      r["timestamp"],
            })

        # ── SMTP oturumları ───────────────────────────────────────────────
        smtp_sessions = []
        rows = conn.execute(
            """
            SELECT source_ip, destination_ip, message, timestamp
            FROM normalized_logs
            WHERE event_action = 'smtp_session'
              AND timestamp >= ?
              AND tenant_id = ?
            ORDER BY timestamp DESC
            LIMIT 30
            """,
            [since, tenant_id],
        ).fetchall()
        for r in rows:
            smtp_sessions.append({
                "source_ip":      r["source_ip"],
                "destination_ip": r["destination_ip"],
                "message":        r["message"],
                "timestamp":      r["timestamp"],
            })

        # ── En aktif kaynak IP'ler (Zeek) ─────────────────────────────────
        top_sources = []
        rows = conn.execute(
            """
            SELECT source_ip, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE source_type = 'zeek'
              AND source_ip IS NOT NULL
              AND timestamp >= ?
              AND tenant_id = ?
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT 10
            """,
            [since, tenant_id],
        ).fetchall()
        for r in rows:
            top_sources.append({"ip": r["source_ip"], "count": r["cnt"]})

        # ── DNS sorgu sayısı ve en çok sorgulanan domainler ───────────────
        dns_top = []
        rows = conn.execute(
            """
            SELECT message, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE event_action = 'dns_query'
              AND timestamp >= ?
              AND tenant_id = ?
            GROUP BY message
            ORDER BY cnt DESC
            LIMIT 10
            """,
            [since, tenant_id],
        ).fetchall()
        for r in rows:
            dns_top.append({"query": r["message"], "count": r["cnt"]})

        # ── Zaman serisi: Zeek olayları saatlik ───────────────────────────
        timeline = []
        rows = conn.execute(
            """
            SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) AS hour,
                   COUNT(*) AS cnt
            FROM normalized_logs
            WHERE source_type = 'zeek'
              AND timestamp >= ?
              AND tenant_id = ?
            GROUP BY hour
            ORDER BY hour ASC
            """,
            [since, tenant_id],
        ).fetchall()
        for r in rows:
            timeline.append({"t": r["hour"], "v": r["cnt"]})

        # ── Özet sayaçlar ─────────────────────────────────────────────────
        summary = {
            "ja3_suspicious_count":    len(ja3_suspicious),
            "ssl_anomaly_count":       len(ssl_anomalies),
            "self_signed_cert_count":  len(self_signed_certs),
            "ftp_sensitive_count":     len(ftp_sensitive),
            "smtp_session_count":      len(smtp_sessions),
            "zeek_total_24h":          sum(zeek_distribution.values()),
        }

    return {
        "hours":              hours,
        "summary":            summary,
        "zeek_distribution":  zeek_distribution,
        "ja3_suspicious":     ja3_suspicious,
        "ssl_anomalies":      ssl_anomalies,
        "self_signed_certs":  self_signed_certs,
        "ftp_sensitive":      ftp_sensitive,
        "smtp_sessions":      smtp_sessions,
        "top_sources":        top_sources,
        "dns_top":            dns_top,
        "timeline":           timeline,
    }
