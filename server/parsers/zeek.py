"""
Zeek JSON log parsers.

Desteklenen log türleri: dns, http, conn, ssl, ssh, notice, x509, smtp, ftp
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


# Kaynak: Salesforce/ja3, ThreatFox, JA3er.com, abuse.ch, Elastic Security Research
# Her hash yanında C2/malware ailesi ve MITRE T-kodu belirtilmiş.
# NOT: Chrome 110+ (Şubat 2023) her bağlantıda farklı JA3 üretiyor; JA3 yanlış pozitif
# riski taşır. Birincil tespit JA4'e taşındı; JA3 legacy cihazlar için fallback.
_KNOWN_BAD_JA3: frozenset[str] = frozenset({
    # ── CobaltStrike ──────────────────────────────────────────────────
    "eb98490965ef2e4b59f45dd72b4c9c24",  # CS default profile     T1071.001
    "a0e9f5d64349fb13191bc781f81f42e1",  # CS malleable profile   T1071.001
    "6d4e940c98d2979e5e5cbfe34a7e0da7",  # CS 4.x Beacon          T1071.001
    # ── Metasploit / Meterpreter ──────────────────────────────────────
    "e7d705a3286e19ea42f587b6125390af",  # Metasploit             T1571
    "b32309a26951912be7dba376398d2d3f",  # MSF reverse_tcp        T1571
    # ── RAT families ──────────────────────────────────────────────────
    "b386946a5a44d1ddcc843bc75336dfce",  # AsyncRAT               T1219
    "1aa7bf8b40a9cd6b4d94c36be23ff2e6",  # NanoCore RAT           T1219
    "54328bd36c14bd82ddaa0c04b25ed9ad",  # QuasarRAT              T1219
    "e0d8d0a00d8f7d2a3a5e9a5aeef9a0e5",  # DarkComet              T1219
    # ── Banking trojans / loaders ─────────────────────────────────────
    "6bea65232d2734134bba30000e986c38",  # Dridex / Emotet        T1566
    "6734f37431670b3ab4292b8f60f29984",  # TrickBot               T1566
    "18e1e491ff5f0a27ba64fc428042800e",  # IcedID / BokBot        T1566
    # ── C2 frameworks (open-source) ───────────────────────────────────
    "de9f102177f91c1b95c6b1d1aadc8e7c",  # Sliver C2              T1071.001
    "c12f54a3f91dc7bafd92cb59fe009a35",  # Havoc C2               T1071.001
    # ── Scanning / recon tools ────────────────────────────────────────
    "d9f72d2e2b5e58e4d58f3e6e3a5a0e60",  # Nmap SSL probe         T1046
    # ── Exploit kits ──────────────────────────────────────────────────
    "c35f59b9517c4b87e17bc7cf7d94a2f7",  # Hancitor dropper       T1203
})

# Kaynak: FoxIO JA4 Database (ja4db.com), Elastic Security Research, Hunt.io
# JA4 format: {protocol}{tls_ver}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
# Chrome 110+ dahil tüm modern istemcilerde deterministik — JA3'ün yerini almaktadır.
_KNOWN_BAD_JA4: frozenset[str] = frozenset({
    # ── CobaltStrike ──────────────────────────────────────────────────
    "t13d1516h2_8daaf6152771_b0da82dd1658",  # CS 4.x default beacon   T1071.001
    "t12d1516h2_8daaf6152771_b0da82dd1658",  # CS 4.x TLS 1.2 fallback T1071.001
    # ── Metasploit / Meterpreter ──────────────────────────────────────
    "t13d191000_9dc949149365_97f8aa674fd9",  # MSF 6.x reverse_tcp     T1571
    # ── C2 frameworks (open-source) ───────────────────────────────────
    "t13d881000_d4bb11353d5b_b0da82dd1658",  # Sliver C2               T1071.001
    "t13d190900_9dc949149365_e7c285222651",  # Havoc C2                T1071.001
    # ── RAT families ──────────────────────────────────────────────────
    "t13d190900_9dc949149365_5a92aefeae2d",  # AsyncRAT / QuasarRAT    T1219
})


def parse_ssl(row: dict) -> Optional[NormalizedLog]:
    sni = row.get("server_name") or ""
    validation = row.get("validation_status") or ""
    subject = row.get("subject") or ""
    ja3 = row.get("ja3") or ""
    ja3s = row.get("ja3s") or ""
    ja4 = row.get("ja4") or ""
    ja4s = row.get("ja4s") or ""

    if sni == "-":
        sni = ""
    if validation == "-":
        validation = ""
    if ja3 == "-":
        ja3 = ""
    if ja3s == "-":
        ja3s = ""
    if ja4 == "-":
        ja4 = ""
    if ja4s == "-":
        ja4s = ""

    label = sni or subject or row.get("id.resp_h", "unknown")
    _BAD_VALIDATION = ("fail", "expire", "invalid", "error", "unable", "self signed")
    bad_cert = any(kw in validation.lower() for kw in _BAD_VALIDATION)
    bad_ja4 = ja4.lower() in _KNOWN_BAD_JA4
    bad_ja3 = ja3.lower() in _KNOWN_BAD_JA3

    if bad_ja4 or bad_ja3:
        severity = "critical"
        event_action = "tls_suspicious_fingerprint"
    elif bad_cert:
        severity = "warning"
        event_action = "ssl_connection"
    else:
        severity = "info"
        event_action = "ssl_connection"

    msg_parts = [f"SSL/TLS {label}"]
    if validation:
        msg_parts.append(f"({validation})")
    if ja4:
        msg_parts.append(f"JA4={ja4[:12]}…")
        if bad_ja4:
            msg_parts.append("[KNOWN_MALWARE_JA4]")
    elif ja3:
        msg_parts.append(f"JA3={ja3[:8]}…")
        if bad_ja3:
            msg_parts.append("[KNOWN_MALWARE_JA3]")

    extra: dict = {}
    if ja4:
        extra["ja4"] = ja4
    if ja4s:
        extra["ja4s"] = ja4s
    if ja3:
        extra["ja3"] = ja3
    if ja3s:
        extra["ja3s"] = ja3s

    tags = ["zeek", "ssl"]
    if bad_ja4:
        tags.append("ja4_malware")
    if bad_ja3:
        tags.append("ja3_malware")

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
        destination_port=_port(row.get("id.resp_p")),
        network_protocol="tcp",
        message=" ".join(msg_parts),
        extra=extra,
        tags=tags,
    )


def parse_x509(row: dict) -> Optional[NormalizedLog]:
    """x509.log → sertifika bilgileri."""
    subject_cn = ""
    issuer_cn = ""

    cert = row.get("certificate") or {}
    if isinstance(cert, dict):
        subject_cn = cert.get("subject", "") or ""
        issuer_cn = cert.get("issuer", "") or ""
        not_valid_after = cert.get("not_valid_after")
    else:
        not_valid_after = None

    if subject_cn == "-":
        subject_cn = ""
    if issuer_cn == "-":
        issuer_cn = ""

    self_signed = subject_cn and issuer_cn and subject_cn == issuer_cn
    severity = "warning" if self_signed else "info"

    msg = f"X.509 cert: {subject_cn or 'unknown'}"
    if issuer_cn and not self_signed:
        msg += f" issued by {issuer_cn}"
    if self_signed:
        msg += " [SELF-SIGNED]"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action="x509_certificate",
        source_ip=None,
        destination_ip=None,
        network_protocol="tcp",
        message=msg,
        extra={
            "subject": subject_cn,
            "issuer": issuer_cn,
            "self_signed": self_signed,
        },
        tags=["zeek", "x509"] + (["self_signed"] if self_signed else []),
    )


def parse_smtp(row: dict) -> Optional[NormalizedLog]:
    """smtp.log → email event."""
    mailfrom = row.get("mailfrom") or ""
    rcptto = row.get("rcptto") or []
    subject = row.get("subject") or ""

    if mailfrom == "-":
        mailfrom = ""
    if subject == "-":
        subject = ""
    if isinstance(rcptto, list):
        rcptto_str = ", ".join(str(r) for r in rcptto[:3])
    else:
        rcptto_str = str(rcptto) if rcptto and rcptto != "-" else ""

    if not mailfrom and not rcptto_str:
        return None

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity="info",
        event_category=LogCategory.NETWORK,
        event_action="smtp_session",
        source_ip=row.get("id.orig_h"),
        destination_ip=row.get("id.resp_h"),
        destination_port=_port(row.get("id.resp_p")),
        network_protocol="tcp",
        message=f"SMTP from={mailfrom} to={rcptto_str}" + (f" subj={subject[:60]}" if subject else ""),
        extra={"mailfrom": mailfrom, "rcptto": rcptto_str, "subject": subject},
        tags=["zeek", "smtp"],
    )


def parse_ftp(row: dict) -> Optional[NormalizedLog]:
    """ftp.log → FTP komutu."""
    command = row.get("command") or ""
    arg = row.get("arg") or ""
    reply_code = row.get("reply_code")
    user = row.get("user") or ""

    if command == "-" or not command:
        return None
    if arg == "-":
        arg = ""
    if user == "-":
        user = ""

    try:
        code = int(reply_code) if reply_code and reply_code != "-" else 0
    except (ValueError, TypeError):
        code = 0

    _SENSITIVE = {"RETR", "STOR", "DELE", "RMD", "MKD", "RNFR", "RNTO"}
    severity = "warning" if command.upper() in _SENSITIVE else "info"

    msg = f"FTP {command}"
    if user:
        msg += f" user={user}"
    if arg:
        msg += f" arg={arg[:60]}"
    if code:
        msg += f" reply={code}"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action="ftp_command",
        source_ip=row.get("id.orig_h"),
        destination_ip=row.get("id.resp_h"),
        destination_port=_port(row.get("id.resp_p")),
        network_protocol="tcp",
        message=msg,
        extra={"command": command, "arg": arg, "user": user, "reply_code": code},
        tags=["zeek", "ftp"] + (["ftp_sensitive"] if command.upper() in _SENSITIVE else []),
    )
