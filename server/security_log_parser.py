"""
NetGuard Server — Auth Log Parser

/var/log/auth.log dosyasını okur, güvenlik olaylarını tespit eder:
  - Başarısız SSH girişleri (brute force tespiti dahil)
  - Başarılı SSH girişleri
  - sudo kullanımları

Brute force eşiği: 5 dakikada aynı IP'den 5+ başarısız giriş.
"""

import json
import logging
import os
import re
import socket
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from shared.models import SecurityEvent, SecurityEventType, NormalizedLog, LogSourceType, LogCategory
from server.database import db

logger = logging.getLogger(__name__)

AUTH_LOG_PATH = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
_STATE_FILE   = os.getenv("NETGUARD_LOG_STATE_FILE", "/tmp/netguard_log_state.json")

BRUTE_FORCE_THRESHOLD = 5        # Kaç başarısız girişten sonra brute force sayılır
BRUTE_FORCE_WINDOW_MIN = 5       # Kaç dakika içinde

# --- Regex desenleri ---
# Başarısız SSH: "Failed password for root from 1.2.3.4 port 22 ssh2"
# veya:          "Failed password for invalid user foo from 1.2.3.4 port 22 ssh2"
_RE_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port"
)

# Başarılı SSH: "Accepted password for mehmet from 1.2.3.4 port 22 ssh2"
# veya:         "Accepted publickey for mehmet from 1.2.3.4 port 22 ssh2"
_RE_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port"
)

# sudo: "mehmet : TTY=pts/0 ; PWD=/home/mehmet ; USER=root ; COMMAND=/bin/bash"
_RE_SUDO = re.compile(
    r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)"
)

# Auth.log satır tarih biçimi: "Apr  8 14:23:01"
_RE_DATE = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)


def _parse_log_date(date_str: str) -> datetime:
    """
    "Apr  8 14:23:01" → datetime (UTC, yıl = şu yıl).
    Auth.log yıl içermez — şu yılı kullanıyoruz.
    """
    now = datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(f"{now.year} {date_str.strip()}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return now


_NORMALIZED_EVENT_TYPES = {
    SecurityEventType.SSH_FAILURE: ("ssh_failure", "warning", LogCategory.AUTHENTICATION),
    SecurityEventType.SSH_SUCCESS: ("ssh_success", "info",    LogCategory.AUTHENTICATION),
    SecurityEventType.SUDO_USAGE:  ("sudo_usage",  "warning", LogCategory.SYSTEM),
}


def _make_event(
    event_type: SecurityEventType,
    severity: str,
    message: str,
    occurred_at: datetime,
    agent_id: str,
    hostname: str,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    raw_line: Optional[str] = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id    = str(uuid.uuid4()),
        agent_id    = agent_id,
        hostname    = hostname,
        event_type  = event_type,
        severity    = severity,
        source_ip   = source_ip,
        username    = username,
        message     = message,
        raw_data    = raw_line,
        occurred_at = occurred_at,
    )


def _write_normalized(event: SecurityEvent) -> None:
    """SecurityEvent'i normalized_logs tablosuna da yazar — correlator için."""
    mapping = _NORMALIZED_EVENT_TYPES.get(event.event_type)
    if mapping is None:
        return
    norm_event_type, _, category = mapping
    norm = NormalizedLog(
        log_id      = str(uuid.uuid4()),
        raw_id      = event.event_id,
        source_type = LogSourceType.AUTH_LOG,
        source_host = event.hostname,
        timestamp   = event.occurred_at,
        severity    = event.severity,
        category    = category,
        event_type  = norm_event_type,
        src_ip      = event.source_ip,
        username    = event.username,
        message     = event.message,
    )
    db.save_normalized_log(norm)


def _check_brute_force(source_ip: str, occurred_at: datetime, agent_id: str, hostname: str) -> Optional[SecurityEvent]:
    """
    Son BRUTE_FORCE_WINDOW_MIN dakikada aynı IP'den kaç hata var?
    Eşik aşılırsa brute_force eventi döndür.
    """
    since = (occurred_at - timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)).isoformat()
    count = db.count_recent_failures(source_ip, since)

    if count >= BRUTE_FORCE_THRESHOLD:
        return _make_event(
            event_type  = SecurityEventType.BRUTE_FORCE,
            severity    = "critical",
            message     = (
                f"Brute force saldırısı tespit edildi: {source_ip} → "
                f"{count} başarısız giriş / {BRUTE_FORCE_WINDOW_MIN} dakika"
            ),
            occurred_at = occurred_at,
            agent_id    = agent_id,
            hostname    = hostname,
            source_ip   = source_ip,
        )
    return None


def _load_log_state() -> dict:
    try:
        with open(_STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_log_state(state: dict) -> None:
    try:
        with open(_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except OSError as exc:
        logger.warning(f"Log state kaydedilemedi: {exc}")


def _read_new_lines(path: Path) -> list[str]:
    """
    Son okuma pozisyonundan itibaren yeni satırları oku.
    İnode değişmişse (logrotate) veya dosya küçüldüyse baştan oku.
    """
    try:
        stat = path.stat()
    except OSError:
        return []

    state   = _load_log_state()
    key     = str(path)
    saved   = state.get(key, {})
    saved_inode  = saved.get("inode", 0)
    saved_offset = saved.get("offset", 0)

    try:
        with path.open("r", errors="replace") as f:
            if saved_inode == stat.st_ino and saved_offset <= stat.st_size:
                f.seek(saved_offset)
            lines     = f.readlines()
            new_offset = f.tell()
    except OSError:
        return []

    state[key] = {"inode": stat.st_ino, "offset": new_offset}
    _save_log_state(state)
    return lines


def parse_auth_log(
    agent_id: str,
    log_path: str = AUTH_LOG_PATH,
) -> list[SecurityEvent]:
    """
    Auth log dosyasını okur, son okumadan bu yana gelen yeni satırları işler.
    İnode + offset takibiyle duplicate event üretilmez.
    Bulunan olaylar otomatik olarak SQLite'a kaydedilir.
    """
    path = Path(log_path)
    if not path.exists():
        logger.warning(f"Auth log bulunamadı: {log_path}")
        return []

    hostname = socket.gethostname()
    events: list[SecurityEvent] = []

    try:
        lines = _read_new_lines(path)
    except PermissionError:
        logger.error(f"Auth log okuma izni yok: {log_path} — sudo gerekli")
        return []

    for line in lines:
        date_match = _RE_DATE.match(line)
        occurred_at = _parse_log_date(date_match.group(1)) if date_match else datetime.now(timezone.utc)

        # Başarısız SSH girişi
        m = _RE_FAILED.search(line)
        if m:
            username, source_ip = m.group(1), m.group(2)
            event = _make_event(
                event_type  = SecurityEventType.SSH_FAILURE,
                severity    = "warning",
                message     = f"Başarısız SSH girişi: kullanıcı={username} kaynak={source_ip}",
                occurred_at = occurred_at,
                agent_id    = agent_id,
                hostname    = hostname,
                source_ip   = source_ip,
                username    = username,
                raw_line    = line.strip(),
            )
            db.save_security_event(event)
            _write_normalized(event)
            events.append(event)

            # Brute force kontrolü
            bf = _check_brute_force(source_ip, occurred_at, agent_id, hostname)
            if bf:
                db.save_security_event(bf)
                events.append(bf)
            continue

        # Başarılı SSH girişi
        m = _RE_ACCEPTED.search(line)
        if m:
            username, source_ip = m.group(1), m.group(2)
            event = _make_event(
                event_type  = SecurityEventType.SSH_SUCCESS,
                severity    = "info",
                message     = f"Başarılı SSH girişi: kullanıcı={username} kaynak={source_ip}",
                occurred_at = occurred_at,
                agent_id    = agent_id,
                hostname    = hostname,
                source_ip   = source_ip,
                username    = username,
                raw_line    = line.strip(),
            )
            db.save_security_event(event)
            _write_normalized(event)
            events.append(event)
            continue

        # sudo kullanımı
        m = _RE_SUDO.search(line)
        if m:
            username, command = m.group(1), m.group(2).strip()
            event = _make_event(
                event_type  = SecurityEventType.SUDO_USAGE,
                severity    = "warning",
                message     = f"sudo kullanıldı: kullanıcı={username} komut={command}",
                occurred_at = occurred_at,
                agent_id    = agent_id,
                hostname    = hostname,
                username    = username,
                raw_line    = line.strip(),
            )
            db.save_security_event(event)
            _write_normalized(event)
            events.append(event)

    logger.info(f"Auth log tarandı: {len(events)} olay bulundu")
    return events


