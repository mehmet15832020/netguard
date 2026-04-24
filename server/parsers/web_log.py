"""
NetGuard — Web Server Log Parser

Desteklenen formatlar:
  - nginx/Apache Combined Log Format (access log)
  - nginx Error Log Format

Her parser bir NormalizedLog üretir veya None döner.
"""

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from shared.models import LogCategory, LogSourceType, NormalizedLog

logger = logging.getLogger(__name__)

# Combined Log Format:
# 1.2.3.4 - frank [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.1" 200 1234 "referer" "UA"
_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+'          # remote_addr
    r'\S+\s+'                   # ident (usually -)
    r'(?P<user>\S+)\s+'         # auth user
    r'\[(?P<time>[^\]]+)\]\s+'  # [timestamp]
    r'"(?P<method>\S+)\s+'      # "METHOD
    r'(?P<path>\S+)\s+'         # /path
    r'(?P<proto>\S+)"\s+'       # HTTP/1.1"
    r'(?P<status>\d{3})\s+'     # status code
    r'(?P<bytes>\d+|-)'         # bytes sent
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'  # referer + UA (combined only)
)

# nginx error log:
# 2024/04/24 10:00:01 [error] 12#12: *1 message, client: 1.2.3.4, server: ...
_NGINX_ERROR_RE = re.compile(
    r'^(?P<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'\d+#\d+:\s+\*?\d*\s*'
    r'(?P<msg>.+?)(?:,\s*client:\s*(?P<ip>[\d.]+))?(?:,\s*server:|$)'
)

_COMBINED_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"
_NGINX_ERROR_FMT   = "%Y/%m/%d %H:%M:%S"

_NGINX_LEVEL_MAP = {
    "emerg": "critical", "alert": "critical", "crit": "critical",
    "error": "high", "warn": "warning", "notice": "info",
    "info": "info", "debug": "info",
}


def _parse_combined_time(raw: str) -> datetime:
    try:
        return datetime.strptime(raw, _COMBINED_TIME_FMT)
    except ValueError:
        return datetime.now(timezone.utc)


def _status_to_event(status: int) -> tuple[str, str]:
    """(event_type, severity)"""
    if status in (401, 403):
        return "web_auth_fail", "warning"
    if 400 <= status < 500:
        return "web_client_error", "info"
    if status >= 500:
        return "web_server_error", "warning"
    return "web_request", "info"


def _make_log(
    source_type: LogSourceType,
    source_host: str,
    event_type: str,
    severity: str,
    message: str,
    raw_content: str,
    timestamp: Optional[datetime] = None,
    src_ip: Optional[str] = None,
    username: Optional[str] = None,
    protocol: Optional[str] = None,
    extra: Optional[dict] = None,
) -> NormalizedLog:
    return NormalizedLog(
        log_id      = str(uuid.uuid4()),
        raw_id      = str(uuid.uuid4()),
        source_type = source_type,
        source_host = source_host,
        timestamp   = timestamp or datetime.now(timezone.utc),
        severity    = severity,
        category    = LogCategory.NETWORK,
        event_type  = event_type,
        src_ip      = src_ip,
        username    = None if username in (None, "-") else username,
        protocol    = protocol,
        message     = message,
        tags        = [],
        extra       = extra or {},
    )


def parse_access_log(line: str, source_host: str = "webserver") -> Optional[NormalizedLog]:
    """nginx veya Apache Combined Log Format access satırı."""
    m = _COMBINED_RE.match(line)
    if not m:
        return None

    ip       = m.group("ip")
    user     = m.group("user")
    method   = m.group("method")
    path     = m.group("path")
    proto    = m.group("proto")
    status   = int(m.group("status"))
    raw_time = m.group("time")
    ua       = m.group("ua") or ""
    referer  = m.group("referer") or ""
    ts       = _parse_combined_time(raw_time)

    event_type, severity = _status_to_event(status)
    msg = f'{method} {path} → {status}'

    return _make_log(
        source_type = LogSourceType.NGINX,
        source_host = source_host,
        event_type  = event_type,
        severity    = severity,
        message     = msg,
        raw_content = line,
        timestamp   = ts,
        src_ip      = ip,
        username    = user,
        protocol    = proto.split("/")[0].lower() if "/" in proto else proto.lower(),
        extra       = {
            "method": method,
            "path": path,
            "status": status,
            "user_agent": ua,
            "referer": referer,
        },
    )


def parse_nginx_error(line: str, source_host: str = "webserver") -> Optional[NormalizedLog]:
    """nginx error log satırı."""
    m = _NGINX_ERROR_RE.match(line)
    if not m:
        return None

    raw_time = m.group("time")
    level    = m.group("level").lower()
    msg_raw  = m.group("msg").strip()
    ip       = m.group("ip")

    try:
        ts = datetime.strptime(raw_time, _NGINX_ERROR_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        ts = datetime.now(timezone.utc)

    severity = _NGINX_LEVEL_MAP.get(level, "info")

    return _make_log(
        source_type = LogSourceType.NGINX,
        source_host = source_host,
        event_type  = "web_error",
        severity    = severity,
        message     = f"nginx [{level}]: {msg_raw}",
        raw_content = line,
        timestamp   = ts,
        src_ip      = ip,
        extra       = {"level": level, "raw_msg": msg_raw},
    )


def detect_and_parse(line: str, source_host: str = "webserver") -> Optional[NormalizedLog]:
    """Web log satırını otomatik tespit et ve parse et."""
    stripped = line.strip()
    if not stripped:
        return None
    # nginx error log: yıl/ay/gün formatıyla başlar
    if re.match(r'^\d{4}/\d{2}/\d{2}', stripped):
        return parse_nginx_error(stripped, source_host)
    return parse_access_log(stripped, source_host)
