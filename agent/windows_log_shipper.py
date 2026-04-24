"""
NetGuard Windows Agent — Windows Event Log okuyucu

Windows Security Event Log'dan 4624/4625/4688 event'lerini okur,
NetGuard sunucusuna gönderir.

Gereksinim: pywin32 (pip install pywin32)
Yalnızca Windows'ta çalışır.
"""

import logging
import os
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

SHIP_INTERVAL = int(os.getenv("WIN_SHIP_INTERVAL", "15"))
BATCH_SIZE    = 50
POSITION_FILE = os.getenv("WIN_LOG_POSITION_FILE", r"C:\ProgramData\NetGuard\win_pos.txt")

# Windows Event IDs
EID_LOGON_SUCCESS = 4624
EID_LOGON_FAILURE = 4625
EID_PROCESS_CREATE = 4688

WATCHED_EVENT_IDS = {EID_LOGON_SUCCESS, EID_LOGON_FAILURE, EID_PROCESS_CREATE}

_LOGON_TYPES = {
    "2":  "interactive",
    "3":  "network",
    "4":  "batch",
    "5":  "service",
    "7":  "unlock",
    "8":  "network_cleartext",
    "10": "remote_interactive",
    "11": "cached_interactive",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_position() -> int:
    try:
        return int(Path(POSITION_FILE).read_text().strip())
    except Exception:
        return 0


def _write_position(record_number: int) -> None:
    try:
        p = Path(POSITION_FILE)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(str(record_number))
    except Exception:
        pass


def _parse_event(event) -> Optional[dict]:
    """win32evtlog event nesnesini NetGuard formatına dönüştürür."""
    try:
        import win32evtlogutil
        eid = event.EventID & 0xFFFF
        if eid not in WATCHED_EVENT_IDS:
            return None

        strings = event.StringInserts or []
        occurred_at = event.TimeGenerated.Format() if hasattr(event.TimeGenerated, "Format") else _now_iso()

        if eid == EID_LOGON_FAILURE:
            username  = strings[5] if len(strings) > 5 else "unknown"
            source_ip = strings[19] if len(strings) > 19 else None
            if source_ip in ("-", "", None):
                source_ip = None
            return {
                "event_type": "windows_logon_failure",
                "severity":   "warning",
                "username":   username,
                "source_ip":  source_ip,
                "message":    f"Windows oturum açma başarısız: kullanıcı={username}",
                "raw_data":   f"EventID=4625 user={username} src={source_ip}",
                "occurred_at": occurred_at,
            }

        if eid == EID_LOGON_SUCCESS:
            username    = strings[5]  if len(strings) > 5  else "unknown"
            source_ip   = strings[18] if len(strings) > 18 else None
            logon_type  = strings[8]  if len(strings) > 8  else "?"
            logon_label = _LOGON_TYPES.get(logon_type, logon_type)
            if source_ip in ("-", "", None):
                source_ip = None
            if logon_label in ("service", "batch"):
                return None
            return {
                "event_type": "windows_logon_success",
                "severity":   "info",
                "username":   username,
                "source_ip":  source_ip,
                "message":    f"Windows oturum açıldı: kullanıcı={username} tür={logon_label}",
                "raw_data":   f"EventID=4624 user={username} type={logon_label} src={source_ip}",
                "occurred_at": occurred_at,
            }

        if eid == EID_PROCESS_CREATE:
            subject_user = strings[1] if len(strings) > 1 else "unknown"
            process_name = strings[5] if len(strings) > 5 else "unknown"
            cmdline      = strings[8] if len(strings) > 8 else ""
            return {
                "event_type": "windows_process_create",
                "severity":   "info",
                "username":   subject_user,
                "source_ip":  None,
                "message":    f"Süreç oluşturuldu: {process_name}",
                "raw_data":   f"EventID=4688 user={subject_user} process={process_name} cmd={cmdline}",
                "occurred_at": occurred_at,
            }

    except Exception as exc:
        logger.debug(f"Event parse hatası: {exc}")
    return None


def _collect_new_events() -> list[dict]:
    """Security kanalından son okunan kaydın sonrasını okur."""
    try:
        import win32evtlog
        import win32con

        last_record = _read_position()
        handle = win32evtlog.OpenEventLog(None, "Security")
        flags  = win32con.EVENTLOG_BACKWARDS_READ | win32con.EVENTLOG_SEQUENTIAL_READ
        total  = win32evtlog.GetNumberOfEventLogRecords(handle)

        events_out: list[dict] = []
        max_record = last_record

        while True:
            records = win32evtlog.ReadEventLog(handle, flags, 0)
            if not records:
                break
            for rec in records:
                if rec.RecordNumber <= last_record:
                    break
                if rec.RecordNumber > max_record:
                    max_record = rec.RecordNumber
                parsed = _parse_event(rec)
                if parsed:
                    events_out.append(parsed)

        win32evtlog.CloseEventLog(handle)

        if max_record > last_record:
            _write_position(max_record)

        return list(reversed(events_out))

    except ImportError:
        logger.error("pywin32 kurulu değil: pip install pywin32")
        return []
    except Exception as exc:
        logger.warning(f"Event Log okuma hatası: {exc}")
        return []


class WindowsLogShipper:
    def __init__(self, server_url: str, api_key: str):
        self._server_url = server_url.rstrip("/")
        self._api_key    = api_key
        self._hostname   = socket.gethostname()
        self._client     = httpx.Client(timeout=10, verify=False)
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not sys.platform.startswith("win"):
            logger.warning("WindowsLogShipper yalnızca Windows'ta çalışır.")
            return
        if not self._api_key:
            logger.warning("NETGUARD_API_KEY tanımlı değil — Windows log shipper devre dışı")
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("Windows Log Shipper başlatıldı.")

    def _loop(self) -> None:
        while True:
            try:
                events = _collect_new_events()
                if events:
                    self._ship(events)
            except Exception as exc:
                logger.warning(f"Windows Log Shipper döngü hatası: {exc}")
            time.sleep(SHIP_INTERVAL)

    def _ship(self, events: list[dict]) -> None:
        url = f"{self._server_url}/api/v1/agents/security-events"
        for i in range(0, len(events), BATCH_SIZE):
            batch = events[i:i + BATCH_SIZE]
            try:
                resp = self._client.post(
                    url,
                    json={"hostname": self._hostname, "events": batch},
                    headers={"X-API-Key": self._api_key},
                )
                resp.raise_for_status()
                logger.info(f"Windows Log Shipper: {len(batch)} olay gönderildi.")
            except Exception as exc:
                logger.warning(f"Windows Log Shipper gönderim hatası: {exc}")
