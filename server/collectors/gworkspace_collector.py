"""
NetGuard — Google Workspace Audit Log Collector

Admin Reports API'den login, admin ve drive audit eventlerini çeker.

Auth: Service Account + Domain-Wide Delegation (google-auth, hafif bağımlılık).
Polling: GWS_POLL_INTERVAL saniyede bir (varsayılan 900s = 15 dk).
Adaptif backoff: 3 art arda boş poll → interval 2×'e çıkar (max 30 dk).

Gerekli env vars (eksikse collector sessizce skip eder):
  GWS_SERVICE_ACCOUNT_JSON  — Service account JSON key dosyasının tam yolu
  GWS_ADMIN_EMAIL           — Impersonate edilecek admin e-posta
  GWS_DOMAIN                — Google Workspace domain (örn: company.com)

Google Workspace Admin Console kurulumu:
  1. GCP'de service account oluştur → JSON key indir
  2. Admin Console → Security → API Controls → Domain-Wide Delegation
  3. Client ID ekle, scope: https://www.googleapis.com/auth/admin.reports.audit.readonly

Kaynak: MITRE ATT&CK T1110/T1114/T1098/T1078/T1530, Google Reports API Docs
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

import httpx

logger = logging.getLogger(__name__)

_SA_JSON_PATH  = os.getenv("GWS_SERVICE_ACCOUNT_JSON", "")
_ADMIN_EMAIL   = os.getenv("GWS_ADMIN_EMAIL", "")
_DOMAIN        = os.getenv("GWS_DOMAIN", "")
_POLL_INTERVAL = int(os.getenv("GWS_POLL_INTERVAL", "900"))
_APPLICATIONS  = ["login", "admin", "drive"]
_SCOPE         = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
_REPORTS_BASE  = "https://admin.googleapis.com/admin/reports/v1"

_gws_token_cache: dict = {}


async def _get_gws_token() -> str:
    """Service Account JWT → Google access token (Domain-Wide Delegation)."""
    import time

    now = time.monotonic()
    if _gws_token_cache.get("expires_at", 0) > now + 60:
        return _gws_token_cache["access_token"]

    try:
        from google.oauth2 import service_account
        import google.auth.transport.requests as google_requests
    except ImportError:
        raise RuntimeError("google-auth kurulu değil: pip install google-auth")

    import json
    with open(_SA_JSON_PATH) as f:
        sa_info = json.load(f)

    credentials = service_account.Credentials.from_service_account_info(
        sa_info,
        scopes=[_SCOPE],
        subject=_ADMIN_EMAIL,
    )
    request = google_requests.Request()
    await asyncio.to_thread(credentials.refresh, request)

    _gws_token_cache["access_token"] = credentials.token
    # credentials.expiry bir datetime nesnesi; gerçek süreyi kullan (varsayılan 3600s fallback)
    import time as _time
    if credentials.expiry:
        _gws_token_cache["expires_at"] = _time.mktime(credentials.expiry.timetuple())
    else:
        _gws_token_cache["expires_at"] = now + 3600
    return credentials.token


async def _fetch_activities(
    client: httpx.AsyncClient,
    token: str,
    application: str,
    since: datetime,
    until: datetime,
) -> list[dict]:
    url = f"{_REPORTS_BASE}/activity/users/all/applications/{application}"
    headers = {"Authorization": f"Bearer {token}"}
    params: dict = {
        "startTime":  since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "endTime":    until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "maxResults": 1000,
    }
    activities: list[dict] = []

    while True:
        resp = await client.get(url, headers=headers, params=params)
        if resp.status_code == 200:
            body = resp.json()
            activities.extend(body.get("items") or [])
            next_page = body.get("nextPageToken")
            if not next_page:
                break
            params["pageToken"] = next_page
        elif resp.status_code == 400:
            logger.debug("GWS %s: zaman aralığında event yok", application)
            break
        else:
            logger.warning("GWS activity [%s]: %s", application, resp.status_code)
            break

    return activities


async def _poll_once(since: datetime, until: datetime) -> int:
    from server.log_store import log_store
    from server.parsers.cloud import parse_gws_event

    try:
        token = await _get_gws_token()
    except Exception as exc:
        logger.error("GWS token alınamadı: %s", exc)
        return 0

    total = 0
    async with httpx.AsyncClient(timeout=30) as client:
        for application in _APPLICATIONS:
            try:
                activities = await _fetch_activities(client, token, application, since, until)
                for activity in activities:
                    log = parse_gws_event(activity, observer_hostname=f"gws-{_DOMAIN}")
                    if log:
                        await asyncio.to_thread(log_store.save, log)
                        total += 1
            except Exception as exc:
                logger.warning("GWS application [%s] hatası: %s", application, exc)

    return total


async def run_gworkspace_collector() -> None:
    if not (_SA_JSON_PATH and _ADMIN_EMAIL and _DOMAIN):
        logger.info("GWorkspace collector devre dışı (GWS_SERVICE_ACCOUNT_JSON/ADMIN_EMAIL/DOMAIN eksik)")
        return

    logger.info("GWorkspace collector başlatıldı (interval=%ds, apps=%s)", _POLL_INTERVAL, _APPLICATIONS)
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
                logger.info("GWorkspace: %d event kaydedildi", count)
            else:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    current_interval = min(_POLL_INTERVAL * 2, 1800)
        except Exception as exc:
            logger.error("GWorkspace collector hatası: %s", exc)

        await asyncio.sleep(current_interval)
