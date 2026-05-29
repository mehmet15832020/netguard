"""
NetGuard — Network Intelligence API

GET /api/v1/network/intelligence — Zeek zenginleştirme özetini döner:
  - Zeek kaynak türlerine göre olay sayıları (24s)
  - JA4/JA3 şüpheli TLS parmak izi tespitleri
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

    data = db.get_network_intelligence(since, tenant_id)

    ja3_suspicious = []
    for r in data["ja3_rows"]:
        msg = r["message"] or ""
        if "KNOWN_MALWARE_JA4" in msg:
            fp_type = "ja4"
        elif "KNOWN_MALWARE_JA3" in msg:
            fp_type = "ja3"
        elif "JA4=" in msg:
            fp_type = "ja4"
        else:
            fp_type = "ja3"
        ja3_suspicious.append({
            "source_ip":        r["source_ip"],
            "destination_ip":   r["destination_ip"],
            "message":          msg,
            "timestamp":        r["timestamp"],
            "fingerprint_type": fp_type,
        })

    ssl_anomalies = [
        {
            "source_ip":      r["source_ip"],
            "destination_ip": r["destination_ip"],
            "message":        r["message"],
            "severity":       r["severity"],
            "timestamp":      r["timestamp"],
        }
        for r in data["ssl_rows"]
    ]
    self_signed_certs = [
        {"source_ip": r["source_ip"], "message": r["message"], "timestamp": r["timestamp"]}
        for r in data["x509_rows"]
    ]
    ftp_sensitive = [
        {
            "source_ip":      r["source_ip"],
            "destination_ip": r["destination_ip"],
            "message":        r["message"],
            "timestamp":      r["timestamp"],
        }
        for r in data["ftp_rows"]
    ]
    smtp_sessions = [
        {
            "source_ip":      r["source_ip"],
            "destination_ip": r["destination_ip"],
            "message":        r["message"],
            "timestamp":      r["timestamp"],
        }
        for r in data["smtp_rows"]
    ]
    top_sources = [{"ip": r["source_ip"], "count": r["cnt"]} for r in data["top_src_rows"]]
    dns_top     = [{"query": r["message"], "count": r["cnt"]} for r in data["dns_rows"]]
    timeline    = [{"t": r["hour"], "v": r["cnt"]} for r in data["timeline_rows"]]

    zeek_distribution = data["zeek_distribution"]
    summary = {
        "ja3_suspicious_count":   len(ja3_suspicious),
        "ssl_anomaly_count":      len(ssl_anomalies),
        "self_signed_cert_count": len(self_signed_certs),
        "ftp_sensitive_count":    len(ftp_sensitive),
        "smtp_session_count":     len(smtp_sessions),
        "zeek_total_24h":         sum(zeek_distribution.values()),
    }

    return {
        "hours":             hours,
        "summary":           summary,
        "zeek_distribution": zeek_distribution,
        "ja3_suspicious":    ja3_suspicious,
        "ssl_anomalies":     ssl_anomalies,
        "self_signed_certs": self_signed_certs,
        "ftp_sensitive":     ftp_sensitive,
        "smtp_sessions":     smtp_sessions,
        "top_sources":       top_sources,
        "dns_top":           dns_top,
        "timeline":          timeline,
    }
