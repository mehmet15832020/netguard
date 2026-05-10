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

_HOUR_EXPR = "to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD\"T\"HH24:00:00\"Z\"')"


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
            f"""
            SELECT event_action, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE source_type = 'zeek'
              AND timestamp >= %s
              AND tenant_id = %s
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
            f"""
            SELECT source_ip, destination_ip, message, timestamp
            FROM normalized_logs
            WHERE event_action = 'tls_suspicious_fingerprint'
              AND timestamp >= %s
              AND tenant_id = %s
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
            f"""
            SELECT source_ip, destination_ip, message, severity, timestamp
            FROM normalized_logs
            WHERE event_action = 'ssl_connection'
              AND severity = 'warning'
              AND timestamp >= %s
              AND tenant_id = %s
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
            f"""
            SELECT source_ip, message, timestamp
            FROM normalized_logs
            WHERE event_action = 'x509_certificate'
              AND severity = 'warning'
              AND timestamp >= %s
              AND tenant_id = %s
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
            f"""
            SELECT source_ip, destination_ip, message, timestamp
            FROM normalized_logs
            WHERE event_action = 'ftp_command'
              AND severity = 'warning'
              AND timestamp >= %s
              AND tenant_id = %s
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
            f"""
            SELECT source_ip, destination_ip, message, timestamp
            FROM normalized_logs
            WHERE event_action = 'smtp_session'
              AND timestamp >= %s
              AND tenant_id = %s
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
            f"""
            SELECT source_ip, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE source_type = 'zeek'
              AND source_ip IS NOT NULL
              AND timestamp >= %s
              AND tenant_id = %s
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
            f"""
            SELECT message, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE event_action = 'dns_query'
              AND timestamp >= %s
              AND tenant_id = %s
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
            f"""
            SELECT {_HOUR_EXPR} AS hour,
                   COUNT(*) AS cnt
            FROM normalized_logs
            WHERE source_type = 'zeek'
              AND timestamp >= %s
              AND tenant_id = %s
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
