"""
NetGuard — Microsoft 365 Audit Log Collector

Office 365 Management Activity API'den Exchange, SharePoint ve
AzureActiveDirectory audit eventlerini çeker.

Auth: Client Credentials (httpx, OAuth2 token endpoint) — msal bağımlılığı yok.
Polling: M365_POLL_INTERVAL saniyede bir (varsayılan 900s = 15 dk).
Adaptif backoff: 3 art arda boş poll → interval 2×'e çıkar (max 30 dk).

Gerekli env vars (eksikse collector sessizce skip eder):
  M365_TENANT_ID      — Azure AD tenant GUID
  M365_CLIENT_ID      — Uygulama (client) ID
  M365_CLIENT_SECRET  — Uygulama client secret

Azure AD app'e gereken izin:
  Office 365 Management APIs → ActivityFeed.Read (application permission)

Kaynak: MITRE ATT&CK T1114/T1098/T1530, Microsoft Management Activity API Reference
"""

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import httpx

logger = logging.getLogger(__name__)

_TENANT_ID     = os.getenv("M365_TENANT_ID", "")
_CLIENT_ID     = os.getenv("M365_CLIENT_ID", "")
_CLIENT_SECRET = os.getenv("M365_CLIENT_SECRET", "")
_POLL_INTERVAL = int(os.getenv("M365_POLL_INTERVAL", "900"))

_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_SCOPE     = "https://manage.office.com/.default"
_API_ROOT  = "https://manage.office.com/api/v1.0/{tenant}"
_WORKLOADS = ["Audit.Exchange", "Audit.SharePoint", "Audit.AzureActiveDirectory"]

_token_cache: dict = {}


async def _get_token() -> str:
    """Client Credentials flow — in-memory token cache."""
    now = time.monotonic()
    if _token_cache.get("expires_at", 0) > now + 60:
        return _token_cache["access_token"]

    url = _TOKEN_URL.format(tenant=_TENANT_ID)
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, data={
            "grant_type":    "client_credentials",
            "client_id":     _CLIENT_ID,
            "client_secret": _CLIENT_SECRET,
            "scope":         _SCOPE,
        })
        resp.raise_for_status()
        body = resp.json()

    _token_cache["access_token"] = body["access_token"]
    _token_cache["expires_at"]   = now + body.get("expires_in", 3600)
    return _token_cache["access_token"]


async def _ensure_subscription(client: httpx.AsyncClient, token: str, workload: str) -> None:
    url = f"{_API_ROOT.format(tenant=_TENANT_ID)}/activity/feed/subscriptions/start"
    resp = await client.post(
        url, params={"contentType": workload},
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    if resp.status_code not in (200, 201):
        logger.debug("M365 subscription %s: %s", workload, resp.status_code)


async def _list_content_blobs(
    client: httpx.AsyncClient,
    token: str,
    workload: str,
    since: datetime,
    until: datetime,
) -> list[str]:
    url = f"{_API_ROOT.format(tenant=_TENANT_ID)}/activity/feed/subscriptions/content"
    headers = {"Authorization": f"Bearer {token}"}
    params = {
        "contentType": workload,
        "startTime":   since.strftime("%Y-%m-%dT%H:%M:%S"),
        "endTime":     until.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    uris: list[str] = []
    next_url: str | None = url
    next_params = params

    while next_url:
        resp = await client.get(next_url, headers=headers, params=next_params)
        if resp.status_code != 200:
            logger.warning("M365 content list [%s]: %s", workload, resp.status_code)
            break
        for item in resp.json():
            if item.get("contentUri"):
                uris.append(item["contentUri"])
        next_url = resp.headers.get("NextPageUri")
        next_params = None

    return uris


async def _fetch_blob(client: httpx.AsyncClient, token: str, uri: str) -> list[dict]:
    resp = await client.get(uri, headers={"Authorization": f"Bearer {token}"})
    if resp.status_code == 200:
        return resp.json()
    logger.warning("M365 content blob %s: HTTP %d", uri.split("?")[0][-40:], resp.status_code)
    return []


async def _poll_once(since: datetime, until: datetime) -> int:
    from server.log_store import log_store
    from server.parsers.cloud import parse_m365_event

    try:
        token = await _get_token()
    except Exception as exc:
        logger.error("M365 token alınamadı: %s", exc)
        return 0

    total = 0
    async with httpx.AsyncClient(timeout=30) as client:
        for workload in _WORKLOADS:
            try:
                await _ensure_subscription(client, token, workload)
                uris = await _list_content_blobs(client, token, workload, since, until)
                for uri in uris:
                    events = await _fetch_blob(client, token, uri)
                    for raw in events:
                        log = parse_m365_event(raw, observer_hostname=f"m365-{_TENANT_ID[:8]}")
                        if log:
                            await asyncio.to_thread(log_store.save, log)
                            total += 1
            except Exception as exc:
                logger.warning("M365 workload [%s] hatası: %s", workload, exc)

    return total


async def run_m365_collector() -> None:
    if not (_TENANT_ID and _CLIENT_ID and _CLIENT_SECRET):
        logger.info("M365 collector devre dışı (M365_TENANT_ID/CLIENT_ID/CLIENT_SECRET eksik)")
        return

    logger.info("M365 collector başlatıldı (interval=%ds)", _POLL_INTERVAL)
    consecutive_empty = 0
    current_interval  = _POLL_INTERVAL

    while True:
        until = datetime.now(timezone.utc)
        since = until - timedelta(seconds=current_interval + 60)

        try:
            count = await _poll_once(since, until)
            if count > 0:
                consecutive_empty = 0
                current_interval  = _POLL_INTERVAL
                logger.info("M365: %d event kaydedildi", count)
            else:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    current_interval = min(_POLL_INTERVAL * 2, 1800)
        except Exception as exc:
            logger.error("M365 collector hatası: %s", exc)

        await asyncio.sleep(current_interval)
