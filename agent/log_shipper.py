"""
NetGuard Agent — Log Shipper

/var/log/auth.log'u tails ederek güvenlik olaylarını NetGuard sunucusuna gönderir.
Position file ile restart'ta duplicate önler.
Thread olarak çalışır, ana agent döngüsünden bağımsızdır.
"""

import logging
import os
import re
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

AUTH_LOG_PATH  = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
POSITION_FILE  = os.getenv("LOG_POSITION_FILE", "/tmp/netguard_auth_pos")
SHIP_INTERVAL  = 10   # saniye
BATCH_SIZE     = 50   # tek seferde max kaç olay gönderilir

_RE_FAILED   = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port")
_RE_ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port")
_RE_SUDO     = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)")


def _parse_line(line: str) -> Optional[dict]:
    """Tek bir auth.log satırını parse eder. Tanınamazsa None döner."""
    if m := _RE_FAILED.search(line):
        return {
            "event_type": "ssh_failure",
            "severity":   "warning",
            "username":   m.group(1),
            "source_ip":  m.group(2),
            "message":    f"Başarısız SSH girişi: kullanıcı={m.group(1)} kaynak={m.group(2)}",
            "raw_data":   line.rstrip(),
            "occurred_at": _now_iso(),
        }
    if m := _RE_ACCEPTED.search(line):
        return {
            "event_type": "ssh_success",
            "severity":   "info",
            "username":   m.group(1),
            "source_ip":  m.group(2),
            "message":    f"Başarılı SSH girişi: kullanıcı={m.group(1)} kaynak={m.group(2)}",
            "raw_data":   line.rstrip(),
            "occurred_at": _now_iso(),
        }
    if m := _RE_SUDO.search(line):
        return {
            "event_type": "sudo_usage",
            "severity":   "info",
            "username":   m.group(1),
            "source_ip":  None,
            "message":    f"Sudo kullanımı: kullanıcı={m.group(1)} komut={m.group(2).strip()}",
            "raw_data":   line.rstrip(),
            "occurred_at": _now_iso(),
        }
    return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_position() -> int:
    try:
        return int(Path(POSITION_FILE).read_text().strip())
    except Exception:
        return 0


def _write_position(pos: int) -> None:
    try:
        Path(POSITION_FILE).write_text(str(pos))
    except Exception:
        pass


def _collect_new_events() -> list[dict]:
    """auth.log'u son okunan pozisyondan itibaren okur, olayları döner."""
    log_path = Path(AUTH_LOG_PATH)
    if not log_path.exists():
        return []

    pos = _read_position()
    current_size = log_path.stat().st_size

    if current_size < pos:
        pos = 0

    events = []
    try:
        with open(log_path, "r", errors="replace") as f:
            f.seek(pos)
            for line in f:
                ev = _parse_line(line)
                if ev:
                    events.append(ev)
            new_pos = f.tell()
        _write_position(new_pos)
    except PermissionError:
        logger.warning(f"auth.log okunamıyor — izin hatası: {AUTH_LOG_PATH}")
    except Exception as e:
        logger.warning(f"auth.log okuma hatası: {e}")

    return events


class LogShipper:
    """Auth.log'u periyodik olarak okuyup sunucuya gönderir."""

    def __init__(self, server_url: str, api_key: str):
        self._server_url = server_url.rstrip("/")
        self._api_key    = api_key
        self._hostname   = socket.gethostname()
        self._client     = httpx.Client(timeout=10)
        self._thread     = threading.Thread(target=self._loop, daemon=True)
        self._stop       = threading.Event()

    def start(self) -> None:
        if not Path(AUTH_LOG_PATH).exists():
            logger.warning(f"auth.log bulunamadı ({AUTH_LOG_PATH}) — log shipper devre dışı")
            return
        if not self._api_key:
            logger.warning("NETGUARD_API_KEY tanımlı değil — log shipper devre dışı")
            return
        self._thread.start()
        logger.info("Log Shipper başlatıldı.")

    def stop(self) -> None:
        self._stop.set()
        self._client.close()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                events = _collect_new_events()
                if events:
                    self._ship(events)
            except Exception as e:
                logger.warning(f"Log Shipper döngü hatası: {e}")
            self._stop.wait(SHIP_INTERVAL)

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
                logger.info(f"Log Shipper: {len(batch)} olay gönderildi.")
            except Exception as e:
                logger.warning(f"Log Shipper gönderim hatası: {e}")
