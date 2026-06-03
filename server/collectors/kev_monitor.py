"""
NetGuard — CISA KEV Monitor

CISA Known Exploited Vulnerabilities kataloğunu günlük olarak çeker,
yeni CVE'leri DB'ye kaydeder ve izlenen vendor'lar için bildirim gönderir.

CIS Controls v8.1 Safeguard 7.1: vulnerability management
Kaynak: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

KEV_URL = os.getenv(
    "CISA_KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)
KEV_FETCH_INTERVAL = int(os.getenv("KEV_FETCH_INTERVAL", str(86400)))  # 24 saat
_HTTP_TIMEOUT = 30.0

# NetGuard ortamında yaygın vendor'lar — bildirimleri bu vendor'larla sınırla
_MONITORED_VENDORS: frozenset[str] = frozenset({
    "cisco", "microsoft", "linux", "opnsense", "vmware",
    "apache", "nginx", "fortinet", "juniper", "palo alto",
    "f5", "citrix", "pulse", "ivanti", "sonicwall",
})


def _parse_entries(raw: dict) -> list[dict]:
    """CISA KEV JSON → upsert için dict listesi."""
    results = []
    for v in raw.get("vulnerabilities", []):
        cve_id = v.get("cveID", "").strip()
        if not cve_id:
            continue
        results.append({
            "cve_id":            cve_id,
            "vendor_project":    v.get("vendorProject", ""),
            "product":           v.get("product", ""),
            "vulnerability_name": v.get("vulnerabilityName", ""),
            "date_added":        v.get("dateAdded"),
            "due_date":          v.get("dueDate"),
            "description":       v.get("shortDescription", ""),
            "required_action":   v.get("requiredAction", ""),
        })
    return results


def _is_monitored(vendor: str) -> bool:
    v = vendor.lower()
    return any(kw in v for kw in _MONITORED_VENDORS)


def _build_notification_body(new_entries: list[dict]) -> str:
    lines = [
        "NetGuard — CISA KEV Yeni CVE Bildirimi",
        "=" * 50,
        f"Tarih: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Yeni CVE sayısı: {len(new_entries)}",
        "",
    ]
    for e in new_entries[:20]:
        lines.append(
            f"  {e['cve_id']}  |  {e['vendor_project']} {e['product']}"
            f"  |  Son tarih: {e.get('due_date', 'N/A')}"
        )
        if e.get("description"):
            lines.append(f"    → {e['description'][:120]}")
        lines.append("")
    if len(new_entries) > 20:
        lines.append(f"  ... ve {len(new_entries) - 20} CVE daha.")
    lines += [
        "=" * 50,
        "Detaylar: https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "Bu mesaj NetGuard KEV Monitor tarafından otomatik gönderilmiştir.",
    ]
    return "\n".join(lines)


async def fetch_kev_once() -> dict:
    """KEV feed'ini bir kez çek, DB'ye kaydet, sonucu döndür."""
    from server.database import db

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            raw = resp.json()
    except httpx.HTTPStatusError as exc:
        logger.error("KEV fetch HTTP hatası: %s", exc)
        return {"status": "error", "detail": str(exc), "new_count": 0}
    except Exception as exc:
        logger.error("KEV fetch hatası: %s", exc)
        return {"status": "error", "detail": str(exc), "new_count": 0}

    entries = _parse_entries(raw)
    if not entries:
        logger.warning("KEV feed boş geldi")
        return {"status": "ok", "total": 0, "new_count": 0}

    new_ids = await asyncio.to_thread(db.upsert_kev_entries, entries)

    if new_ids:
        new_entries = [e for e in entries if e["cve_id"] in set(new_ids)]
        monitored_new = [e for e in new_entries if _is_monitored(e.get("vendor_project", ""))]

        logger.info("KEV: %d yeni CVE eklendi (%d izlenen vendor)", len(new_ids), len(monitored_new))

        if monitored_new:
            _send_kev_notification(monitored_new)
    else:
        logger.debug("KEV: yeni CVE yok (toplam %d)", len(entries))

    return {
        "status": "ok",
        "total":  len(entries),
        "new_count": len(new_ids),
        "catalog_date": raw.get("catalogVersion", ""),
    }


def _send_kev_notification(new_entries: list[dict]) -> None:
    try:
        from server.notifier import notifier
        subject = f"[NetGuard] CISA KEV: {len(new_entries)} yeni CVE izlenen vendor'larda"
        body = _build_notification_body(new_entries)
        notifier.email.send_custom(subject, body)
    except Exception as exc:
        logger.warning("KEV bildirim gönderilemedi: %s", exc)


async def run_kev_monitor() -> None:
    """asyncio task — KEV'i günlük çeker."""
    logger.info("KEV monitor başlatıldı (interval=%ds)", KEV_FETCH_INTERVAL)
    while True:
        result = await fetch_kev_once()
        logger.info("KEV fetch tamamlandı: %s", result)
        await asyncio.sleep(KEV_FETCH_INTERVAL)
