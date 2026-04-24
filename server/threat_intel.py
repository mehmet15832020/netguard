"""
NetGuard — Threat Intelligence

AbuseIPDB ücretsiz API ile IP itibar sorgulama.
Sonuçlar SQLite'a cache'lenir (24 saat TTL).
Konfigürasyon: ABUSEIPDB_API_KEY ortam değişkeni.
"""

import logging
import os
import urllib.request
import urllib.parse
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_API_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
_API_URL   = "https://api.abuseipdb.com/api/v2/check"
_CACHE_TTL = timedelta(hours=24)


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
    )


def _cache_fresh(queried_at: str) -> bool:
    try:
        ts = datetime.fromisoformat(queried_at)
        return datetime.now(timezone.utc) - ts < _CACHE_TTL
    except Exception:
        return False


def lookup(ip: str) -> Optional[dict]:
    """
    IP için AbuseIPDB skoru döndür.
    Önce cache'e bakar (24h TTL), sonra API'ye gider.
    Private IP'ler sorgulanmaz — None döner.
    API key yoksa None döner.
    """
    if _is_private_ip(ip):
        return None

    from server.database import db

    cached = db.get_threat_intel(ip)
    if cached and _cache_fresh(cached["queried_at"]):
        return cached

    if not _API_KEY:
        logger.debug("ABUSEIPDB_API_KEY tanımlı değil, TI atlandı")
        return None

    try:
        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
        req = urllib.request.Request(
            f"{_API_URL}?{params}",
            headers={"Key": _API_KEY, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())["data"]

        score         = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        country_code  = data.get("countryCode", "")
        isp           = data.get("isp", "")

        db.save_threat_intel(ip, score, total_reports, country_code, isp)
        logger.info(f"TI sorgusu: {ip} → score={score} reports={total_reports}")
        return db.get_threat_intel(ip)

    except Exception as exc:
        logger.warning(f"AbuseIPDB sorgusu başarısız [{ip}]: {exc}")
        return None
