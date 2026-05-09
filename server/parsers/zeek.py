"""
Zeek JSON log parsers.

Desteklenen log türleri: dns, http, conn, ssl
Her parser: dict (Zeek JSON satırı) → NormalizedLog | None
"""

import re
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

from shared.models import NormalizedLog, LogSourceType, LogCategory

logger = logging.getLogger(__name__)


def _ts(val) -> datetime:
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(float(val), tz=timezone.utc)
    return datetime.fromisoformat(str(val)).replace(tzinfo=timezone.utc)


def _port(val) -> Optional[int]:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def parse_dns(row: dict) -> Optional[NormalizedLog]:
    query = row.get("query", "")
    if not query or query == "-":
        return None

    answers = row.get("answers", [])
    if isinstance(answers, list):
        answers_str = ", ".join(str(a) for a in answers[:5])
    else:
        answers_str = str(answers) if answers and answers != "-" else ""

    rcode = row.get("rcode_name", "NOERROR")
    qtype = row.get("qtype_name", "A")
    summary = f"{answers_str}" if answers_str else rcode

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity="info",
        event_category=LogCategory.NETWORK,
        event_action="dns_query",
        source_ip=row.get("id.orig_h"),
        destination_ip=row.get("id.resp_h"),
        network_protocol=row.get("proto", "udp"),
        message=f"DNS {qtype} {query} → {summary}",
        tags=["zeek", "dns"],
    )


def parse_http(row: dict) -> Optional[NormalizedLog]:
    method = row.get("method", "")
    if not method or method == "-":
        return None

    host = row.get("host") or row.get("id.resp_h") or ""
    uri = row.get("uri") or "/"
    status = row.get("status_code")

    try:
        status_int = int(status) if status and status != "-" else 0
    except (ValueError, TypeError):
        status_int = 0

    if status_int >= 400:
        event_action = "web_client_error"
        severity = "warning"
    else:
        event_action = "web_request"
        severity = "info"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action=event_action,
        source_ip=row.get("id.orig_h"),
        destination_ip=row.get("id.resp_h"),
        source_port=_port(row.get("id.orig_p")),
        destination_port=_port(row.get("id.resp_p")),
        network_protocol="tcp",
        message=f"HTTP {method} {host}{uri} → {status_int or '-'}",
        tags=["zeek", "http"],
    )


def parse_conn(row: dict) -> Optional[NormalizedLog]:
    state = row.get("conn_state", "")
    try:
        duration = float(row.get("duration") or 0)
    except (ValueError, TypeError):
        duration = 0.0

    # Kısa tamamlanmış bağlantılar atla — çok gürültülü
    if state == "SF" and duration < 2.0:
        return None
    if state not in ("SF", "REJ", "RSTO", "RSTOS0", "S0"):
        return None

    severity = "info" if state == "SF" else "warning"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action="network_connection",
        source_ip=row.get("id.orig_h"),
        destination_ip=row.get("id.resp_h"),
        source_port=_port(row.get("id.orig_p")),
        destination_port=_port(row.get("id.resp_p")),
        network_protocol=row.get("proto", "tcp"),
        message=(
            f"Conn {state}: {row.get('id.orig_h')}:{row.get('id.orig_p')}"
            f" → {row.get('id.resp_h')}:{row.get('id.resp_p')} ({duration:.1f}s)"
        ),
        tags=["zeek", "conn"],
    )


def parse_ssh(row: dict) -> Optional[NormalizedLog]:
    """
    ssh.log satırı → NormalizedLog.

    event_action: ssh_failure veya ssh_success — mevcut sigma kurallarıyla uyumlu.
    auth_success=null (bağlantı devam ediyor) ve auth_attempts=0 → atla.
    """
    auth_success = row.get("auth_success")
    attempts = int(row.get("auth_attempts") or 0)

    if auth_success is None and attempts == 0:
        return None

    if auth_success is True:
        event_action = "ssh_success"
        severity = "warning"
    else:
        event_action = "ssh_failure"
        severity = "info"

    client = row.get("client") or ""
    server = row.get("server") or ""
    label  = f"→ {row.get('id.resp_h')}:{row.get('id.resp_p', 22)}"
    detail = f" attempts={attempts}" if attempts else ""

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.AUTHENTICATION,
        event_action=event_action,
        source_ip=row.get("id.orig_h"),
        destination_ip=row.get("id.resp_h"),
        destination_port=_port(row.get("id.resp_p")),
        network_protocol="tcp",
        message=f"SSH {event_action} {row.get('id.orig_h')} {label}{detail}",
        tags=["zeek", "ssh"],
    )


def parse_notice(row: dict) -> Optional[NormalizedLog]:
    """
    notice.log satırı → NormalizedLog.

    Zeek'in kendi tespitlerini (port scan, brute force, vb.) alır.
    note alanından event_action türetilir.
    """
    note = row.get("note", "")
    if not note or note == "-":
        return None

    msg = row.get("msg") or row.get("sub") or note
    src = row.get("src") or row.get("id.orig_h")
    dst = row.get("dst") or row.get("id.resp_h")

    slug = re.sub(r"[^a-z0-9]+", "_", note.lower()).strip("_")
    event_action = f"zeek_{slug}"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity="warning",
        event_category=LogCategory.INTRUSION,
        event_action=event_action,
        source_ip=src,
        destination_ip=dst,
        network_protocol=row.get("proto"),
        message=f"Zeek Notice [{note}]: {msg}",
        tags=["zeek", "notice"],
    )


def parse_ssl(row: dict) -> Optional[NormalizedLog]:
    sni = row.get("server_name") or ""
    validation = row.get("validation_status") or ""
    subject = row.get("subject") or ""

    if sni == "-":
        sni = ""
    if validation == "-":
        validation = ""

    label = sni or subject or row.get("id.resp_h", "unknown")
    _BAD = ("fail", "expire", "invalid", "error", "unable", "self signed")
    severity = "warning" if any(kw in validation.lower() for kw in _BAD) else "info"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action="ssl_connection",
        source_ip=row.get("id.orig_h"),
        destination_ip=row.get("id.resp_h"),
        destination_port=_port(row.get("id.resp_p")),
        network_protocol="tcp",
        message=f"SSL/TLS {label}" + (f" ({validation})" if validation else ""),
        tags=["zeek", "ssl"],
    )
