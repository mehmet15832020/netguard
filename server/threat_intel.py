"""
NetGuard — Threat Intelligence

Desteklenen kaynaklar:
  - AbuseIPDB    (score >= 70 → critical)
  - Feodo Tracker (Abuse.ch C2 blocklist, in-memory, 24h refresh)
  - ThreatFox    (Abuse.ch IOC, per-IP API, ucretsiz)
  - GreyNoise Community (noise/riot filtresi, GREYNOISE_API_KEY gerekli)

composite_score: 0-100 agirlikli skor (G3-4)
"""

import json
import logging
import os
import time
import threading
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

_GREYNOISE_KEY = os.getenv("GREYNOISE_API_KEY", "")
_GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"

_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_FEODO_TTL = 24 * 3600
_CACHE_TTL = timedelta(hours=24)

# -- Feodo in-memory cache ---------------------------------------------------

_feodo_lock = threading.Lock()
_feodo_last_fetch: float = 0.0
_feodo_data: dict[str, dict] = {}


def _refresh_feodo() -> None:
    global _feodo_last_fetch, _feodo_data
    try:
        req = urllib.request.Request(_FEODO_URL, headers={"User-Agent": "NetGuard/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            items = json.loads(resp.read())
        new_data = {}
        for item in items:
            ip = item.get("ip_address", "")
            if ip:
                new_data[ip] = {
                    "malware": item.get("malware", ""),
                    "port":    item.get("port", 0),
                    "status":  item.get("status", ""),
                }
        with _feodo_lock:
            _feodo_data = new_data
            _feodo_last_fetch = time.monotonic()
        logger.info("Feodo Tracker guncellendi: %d C2 IP", len(new_data))
    except Exception as exc:
        logger.warning("Feodo Tracker cekilemedi: %s", exc)


def _feodo_check(ip: str) -> dict:
    with _feodo_lock:
        stale = (time.monotonic() - _feodo_last_fetch) > _FEODO_TTL
        cached = dict(_feodo_data)
    if stale:
        _refresh_feodo()
        with _feodo_lock:
            cached = dict(_feodo_data)
    entry = cached.get(ip)
    if entry:
        return {"listed": True, "malware": entry["malware"], "port": entry["port"]}
    return {"listed": False, "malware": "", "port": 0}


# -- Yardimci ----------------------------------------------------------------

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


def _cache_fresh(queried_at) -> bool:
    try:
        if isinstance(queried_at, datetime):
            ts = queried_at if queried_at.tzinfo else queried_at.replace(tzinfo=timezone.utc)
        else:
            ts = datetime.fromisoformat(str(queried_at))
        return datetime.now(timezone.utc) - ts < _CACHE_TTL
    except Exception:
        return False


# -- Composite score ---------------------------------------------------------

def _compute_composite(abuseipdb_score: int, feodo_listed: bool,
                        threatfox_score: int, greynoise_noise: bool,
                        greynoise_riot: bool, greynoise_classification: str) -> int:
    score = 0.0
    if feodo_listed:
        score = max(score, 85.0)
    score += abuseipdb_score * 0.30
    score += threatfox_score * 0.25
    if greynoise_classification == "malicious":
        score += 20.0
    if greynoise_noise:
        score = min(score, 40.0)
    if greynoise_riot:
        score = min(score, 20.0)
    return min(100, int(score))


# -- Kaynaklar ---------------------------------------------------------------

def _query_abuseipdb(ip: str) -> Optional[dict]:
    if not _ABUSEIPDB_KEY:
        return None
    try:
        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
        req = urllib.request.Request(
            f"{_ABUSEIPDB_URL}?{params}",
            headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())["data"]
        return {
            "score":         data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code":  data.get("countryCode", ""),
            "isp":           data.get("isp", ""),
        }
    except Exception as exc:
        logger.warning("AbuseIPDB sorgusu basarisiz [%s]: %s", ip, exc)
        return None


def _query_threatfox(ip: str) -> dict:
    try:
        body = json.dumps({"query": "search_ioc", "search_term": ip}).encode()
        req = urllib.request.Request(
            _THREATFOX_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            result = json.loads(resp.read())
        if result.get("query_status") == "ok" and result.get("data"):
            best = max(result["data"], key=lambda x: x.get("confidence_level", 0))
            return {
                "score":   best.get("confidence_level", 0),
                "malware": best.get("malware", ""),
            }
    except Exception as exc:
        logger.warning("ThreatFox sorgusu basarisiz [%s]: %s", ip, exc)
    return {"score": 0, "malware": ""}


def _query_greynoise(ip: str) -> dict:
    if not _GREYNOISE_KEY:
        return {"noise": False, "riot": False, "classification": ""}
    try:
        req = urllib.request.Request(
            _GREYNOISE_URL.format(ip=ip),
            headers={"key": _GREYNOISE_KEY, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        return {
            "noise":          bool(data.get("noise", False)),
            "riot":           bool(data.get("riot", False)),
            "classification": data.get("classification", ""),
        }
    except Exception as exc:
        logger.warning("GreyNoise sorgusu basarisiz [%s]: %s", ip, exc)
        return {"noise": False, "riot": False, "classification": ""}


# -- Ana lookup --------------------------------------------------------------

def lookup(ip: str) -> Optional[dict]:
    """
    IP icin tum TI kaynaklarini sorgular.
    Once cache'e bakar (24h TTL), sonra tum kaynaklari sirayla cagirdir.
    Private IP → None doner.
    """
    if _is_private_ip(ip):
        return None

    from server.database import db

    cached = db.get_threat_intel(ip)
    if cached and _cache_fresh(cached["queried_at"]):
        return cached

    abuseipdb = _query_abuseipdb(ip)
    score         = abuseipdb["score"]         if abuseipdb else 0
    total_reports = abuseipdb["total_reports"] if abuseipdb else 0
    country_code  = abuseipdb["country_code"]  if abuseipdb else (cached or {}).get("country_code", "")
    isp           = abuseipdb["isp"]           if abuseipdb else (cached or {}).get("isp", "")

    feodo = _feodo_check(ip)
    tf    = _query_threatfox(ip)
    gn    = _query_greynoise(ip)

    composite = _compute_composite(
        score, feodo["listed"], tf["score"],
        gn["noise"], gn["riot"], gn["classification"],
    )

    db.save_threat_intel(
        ip=ip, score=score, total_reports=total_reports,
        country_code=country_code, isp=isp,
        feodo_listed=feodo["listed"], feodo_malware=feodo["malware"],
        threatfox_score=tf["score"], threatfox_malware=tf["malware"],
        greynoise_noise=gn["noise"], greynoise_riot=gn["riot"],
        greynoise_classification=gn["classification"],
        composite_score=composite,
    )
    logger.info(
        "TI sorgusu: %s → abuse=%d feodo=%s tf=%d gn_cls=%s composite=%d",
        ip, score, feodo["listed"], tf["score"], gn["classification"], composite,
    )
    return db.get_threat_intel(ip)
