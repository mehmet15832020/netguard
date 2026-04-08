"""
NetGuard Server — Auth Log Parser

/var/log/auth.log dosyasını okur, güvenlik olaylarını tespit eder:
  - Başarısız SSH girişleri (brute force tespiti dahil)
  - Başarılı SSH girişleri
  - sudo kullanımları

Brute force eşiği: 5 dakikada aynı IP'den 5+ başarısız giriş.
"""

import logging
import os
import re
import socket
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from shared.models import SecurityEvent, SecurityEventType
from server.database import db

logger = logging.getLogger(__name__)

AUTH_LOG_PATH = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")

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


def parse_auth_log(
    agent_id: str,
    log_path: str = AUTH_LOG_PATH,
    max_lines: int = 500,
) -> list[SecurityEvent]:
    """
    Auth log dosyasını okur, yeni güvenlik olaylarını döndürür.
    Bulunan olaylar otomatik olarak SQLite'a kaydedilir.

    max_lines: Dosyanın sonundan kaç satır okunacak (kuyruk).
    """
    path = Path(log_path)
    if not path.exists():
        logger.warning(f"Auth log bulunamadı: {log_path}")
        return []

    hostname = socket.gethostname()
    events: list[SecurityEvent] = []

    try:
        lines = _tail(path, max_lines)
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
            events.append(event)

    logger.info(f"Auth log tarandı: {len(events)} olay bulundu")
    return events


def _tail(path: Path, n: int) -> list[str]:
    """Dosyanın son N satırını döndür."""
    with path.open("r", errors="replace") as f:
        return f.readlines()[-n:]
