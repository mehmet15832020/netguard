"""
NetGuard Windows Agent — Multi-Channel Event Log Okuyucu

5 kanaldan Windows event loglarını okur, NetGuard sunucusuna gönderir.
Her kanal için ayrı pozisyon takibi yapılır.

Kanallar ve EID'ler:
  Security:   4624, 4625, 4648, 4672, 4688, 4698, 4702, 4720, 4728,
              4732, 4740, 4768, 4769, 4771, 4776, 5140, 1102,
              4741, 4614, 4703
  Sysmon:     1, 3, 6, 7, 8, 9, 10, 11, 13, 15, 17, 18, 19, 21, 22, 25
  PowerShell: 4103, 4104
  System:     7045, 7034, 7040
  AppLocker:  8004

Gereksinim: pywin32 (pip install pywin32)
Yalnızca Windows'ta çalışır.
"""

import logging
import os
import socket
import sys
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

SHIP_INTERVAL = int(os.getenv("WIN_SHIP_INTERVAL", "15"))
BATCH_SIZE    = 50
POSITION_DIR  = Path(os.getenv("WIN_LOG_POSITION_DIR", r"C:\ProgramData\NetGuard"))

_CHANNELS: dict[str, tuple[str, frozenset[int]]] = {
    "Security": (
        "Security",
        frozenset({
            4624, 4625, 4648, 4672, 4688, 4698, 4702, 4720, 4728,
            4732, 4740, 4768, 4769, 4771, 4776, 5140, 1102,
            4741, 4614, 4703,
        }),
    ),
    "Sysmon": (
        "Microsoft-Windows-Sysmon/Operational",
        frozenset({1, 3, 6, 7, 8, 9, 10, 11, 13, 15, 17, 18, 19, 21, 22, 25}),
    ),
    "PowerShell": (
        "Microsoft-Windows-PowerShell/Operational",
        frozenset({4103, 4104}),
    ),
    "System": (
        "System",
        frozenset({7045, 7034, 7040}),
    ),
    "AppLocker": (
        "Microsoft-Windows-AppLocker/EXE and DLL",
        frozenset({8004}),
    ),
}

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _position_file(channel_name: str) -> Path:
    safe = channel_name.replace("/", "_").replace(" ", "_")
    return POSITION_DIR / f"win_pos_{safe}.txt"


def _read_position(channel_name: str) -> int:
    try:
        return int(_position_file(channel_name).read_text().strip())
    except Exception:
        return 0


def _write_position(channel_name: str, bookmark: int) -> None:
    try:
        p = _position_file(channel_name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(str(bookmark))
    except Exception:
        pass


def _render_event_xml(event_handle) -> Optional[str]:
    try:
        import win32evtlog
        xml_bytes = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
        return xml_bytes if isinstance(xml_bytes, str) else xml_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None


def _collect_channel(channel_name: str) -> list[dict]:
    try:
        import win32evtlog
        from server.evtx_parser import _parse_record_xml
    except ImportError:
        logger.error("pywin32 kurulu değil veya server modülü erişilemiyor")
        return []

    log_name, watched = _CHANNELS[channel_name]
    last_record = _read_position(channel_name)
    max_record  = last_record
    results: list[dict] = []

    try:
        eid_list = " or ".join(f"EventID={e}" for e in sorted(watched))
        xpath    = f"*[System[{eid_list}]]"

        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
        query = win32evtlog.EvtQuery(log_name, flags, xpath)

        if last_record > 0:
            bookmark_xml = (
                f'<BookmarkList><Bookmark Channel="{log_name}" '
                f'RecordId="{last_record}" IsCurrent="true"/></BookmarkList>'
            )
            try:
                bm = win32evtlog.EvtCreateBookmark(bookmark_xml)
                win32evtlog.EvtSeek(query, 1, bm, win32evtlog.EvtSeekRelativeToBookmark)
            except Exception:
                pass

        while True:
            events = win32evtlog.EvtNext(query, 100)
            if not events:
                break
            for evt in events:
                xml_str = _render_event_xml(evt)
                if not xml_str:
                    continue
                try:
                    root = ET.fromstring(xml_str)
                    rec_id_el = root.find(".//{%s}EventRecordID" % _NS)
                    rec_id = int(rec_id_el.text) if rec_id_el is not None and rec_id_el.text else 0
                except Exception:
                    rec_id = 0

                if rec_id > max_record:
                    max_record = rec_id

                parsed = _parse_record_xml(xml_str)
                if parsed:
                    parsed["_channel"] = channel_name
                    results.append(parsed)

    except Exception as exc:
        logger.warning("Kanal okuma hatası [%s]: %s", channel_name, exc)

    if max_record > last_record:
        _write_position(channel_name, max_record)

    return results


class WindowsLogShipper:
    def __init__(self, server_url: str, api_key: str):
        self._server_url = server_url.rstrip("/")
        self._api_key    = api_key
        self._hostname   = socket.gethostname()
        _verify: bool | str = os.getenv("WIN_AGENT_CA_BUNDLE") or \
            os.getenv("WIN_AGENT_VERIFY_TLS", "true").lower() != "false"
        self._client     = httpx.Client(timeout=10, verify=_verify)
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
        logger.info("Windows Log Shipper başlatıldı — %d kanal izleniyor.", len(_CHANNELS))

    def _loop(self) -> None:
        while True:
            try:
                all_events: list[dict] = []
                for channel_name in _CHANNELS:
                    events = _collect_channel(channel_name)
                    all_events.extend(events)
                if all_events:
                    self._ship(all_events)
            except Exception as exc:
                logger.warning("Windows Log Shipper döngü hatası: %s", exc)
            time.sleep(SHIP_INTERVAL)

    def _ship(self, events: list[dict]) -> None:
        url = f"{self._server_url}/api/v1/agents/security-events"
        for i in range(0, len(events), BATCH_SIZE):
            batch = events[i:i + BATCH_SIZE]
            clean = [{k: v for k, v in e.items() if k != "_channel"} for e in batch]
            try:
                resp = self._client.post(
                    url,
                    json={"hostname": self._hostname, "events": clean},
                    headers={"X-API-Key": self._api_key},
                )
                resp.raise_for_status()
                logger.info("Windows Log Shipper: %d olay gönderildi.", len(clean))
            except Exception as exc:
                logger.warning("Windows Log Shipper gönderim hatası: %s", exc)
