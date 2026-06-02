"""
Zeek JSON log parsers.

Desteklenen log türleri: dns, http, conn, ssl, ssh, notice, x509, smtp, ftp, weird, dpd, files
Her parser: dict (Zeek JSON satırı) → NormalizedLog | None
"""

import ipaddress
import os
import re
import uuid
import logging
from datetime import datetime, timezone
from math import log2 as _log2
from typing import Optional

from shared.models import NormalizedLog, LogSourceType, LogCategory

logger = logging.getLogger(__name__)

_DNS_ENTROPY_THRESHOLD = float(os.getenv("DNS_ENTROPY_THRESHOLD", "4.0"))
_DNS_LONG_QUERY_THRESHOLD = int(os.getenv("DNS_LONG_QUERY_THRESHOLD", "50"))
_DNS_ENTROPY_MIN_LABEL_LEN = int(os.getenv("DNS_ENTROPY_MIN_LABEL_LEN", "20"))

_IGNORE_WEIRDS: frozenset[str] = frozenset({
    "window_recision",
    "bad_ACK_number",
    "DNS_RR_unknown_type",
    "dns_A_query_answers_AAAA_question",
    "data_before_established",
    "inappropriate_FIN",
    "window_scale_without_timestamping",
    "above_hole_data_without_any_acks",
    "line_terminated_with_single_CR",
    "TCP_seq_gap_after_window",
})

_SUSPICIOUS_DPD_PORTS: frozenset[int] = frozenset({443, 8443, 8080, 8008, 8888, 9000})

_SUSPICIOUS_DPD_ANALYZERS: frozenset[str] = frozenset({"SSL", "HTTP", "DNS"})

_SUSPICIOUS_MIME_TYPES: frozenset[str] = frozenset({
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-elf",
    "application/x-mach-binary",
    "application/x-sharedlib",
    "application/x-java-applet",
    "application/x-powershell",
    "application/x-sh",
    "application/x-bat",
    "application/x-msaccess",
})


_MULTI_PART_TLD: frozenset[str] = frozenset({
    "co.uk", "com.tr", "com.au", "org.uk", "gov.uk", "co.nz",
    "com.br", "org.au", "net.au", "edu.au", "co.za", "com.cn",
    "com.mx", "com.ar", "co.in", "co.jp", "ne.jp",
})


def _subdomain_labels(query: str) -> list[str]:
    parts = query.rstrip(".").split(".")
    if len(parts) < 2:
        return []
    suffix = f"{parts[-2]}.{parts[-1]}"
    skip = 3 if suffix in _MULTI_PART_TLD else 2
    return parts[:-skip] if len(parts) > skip else []


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    s = s.lower()
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * _log2(v / n) for v in freq.values())


def _ts(val) -> datetime:
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(float(val), tz=timezone.utc)
    return datetime.fromisoformat(str(val)).replace(tzinfo=timezone.utc)


def _port(val) -> Optional[int]:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _is_private(ip: Optional[str]) -> bool:
    if not ip or ip == "-":
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


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

    subdomain_labels = _subdomain_labels(query)
    suspicious_labels = [l for l in subdomain_labels if len(l) >= _DNS_ENTROPY_MIN_LABEL_LEN]
    max_entropy = max((_shannon_entropy(l) for l in suspicious_labels), default=0.0)

    query_len = len(query.rstrip("."))

    indicators: list[str] = []
    severity = "info"

    if max_entropy >= _DNS_ENTROPY_THRESHOLD:
        indicators.append(f"[HIGH_ENTROPY:{max_entropy:.1f}]")
        severity = "high"
    if query_len > _DNS_LONG_QUERY_THRESHOLD:
        indicators.append(f"[LONG_QUERY:{query_len}c]")
        if severity == "info":
            severity = "warning"

    indicator_str = " ".join(indicators)
    message = f"DNS {qtype} {query} → {summary}"
    if indicator_str:
        message = f"{message} {indicator_str}"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action="dns_query",
        source_ip=row.get("id.orig_h"),
        destination_ip=row.get("id.resp_h"),
        source_port=_port(row.get("id.orig_p")),
        destination_port=_port(row.get("id.resp_p")),
        network_protocol=row.get("proto", "udp"),
        message=message,
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

    try:
        resp_body_len = int(row.get("response_body_len") or 0)
    except (ValueError, TypeError):
        resp_body_len = 0

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
        network_bytes=resp_body_len or None,
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

    try:
        orig_bytes = int(row.get("orig_bytes") or 0)
        resp_bytes = int(row.get("resp_bytes") or 0)
        total_bytes = orig_bytes + resp_bytes
    except (ValueError, TypeError):
        total_bytes = 0

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
        network_bytes=total_bytes or None,
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

# JA4 format: {protocol}{tls_ver}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
# Chrome 110+ dahil tüm modern istemcilerde deterministik — JA3'ün yerini almaktadır.
# Kaynak: FoxIO ja4plus-mapping.csv (github.com/FoxIO-LLC/ja4) — doğrulanmış IoC feed.
_KNOWN_BAD_JA4: frozenset[str] = frozenset({
    # ── CobaltStrike ──────────────────────────────────────────────────
    "t13d201100_2b729b4bf6f3_9e7b989ebec8",  # CS beacon               T1071.001
    "t12i190700_d83cc789557e_16bbda4055b2",  # CS v4.9.1 wininet (IP)  T1071.001
    "t12i210700_76e208dd3e22_16bbda4055b2",  # CS v4.9.1 winhttp (IP)  T1071.001
    "t12d190800_d83cc789557e_16bbda4055b2",  # CS v4.9.1 wininet (SNI) T1071.001
    "t12d210800_76e208dd3e22_16bbda4055b2",  # CS v4.9.1 winhttp (SNI) T1071.001
    # ── Sliver (Go crypto/tls) ────────────────────────────────────────
    "t13d190900_9dc949149365_97f8aa674fd9",  # Sliver Agent (domain)   T1071.001
    "t13i190800_9dc949149365_97f8aa674fd9",  # Sliver Agent (IP)       T1071.001
})

# JA4S format: {protocol}{tls_ver}{ext_count}{alpn}_{cipher_hex}_{ext_hash}
# JA4S'te SNI indikatörü (d/i) yoktur; sunucu seçtiği tek cipher hex olarak yazılır.
# JA4 (istemci) + JA4S (sunucu) çift eşleşmesi = en yüksek güven seviyesi.
# Kaynak: FoxIO ja4plus-mapping.csv (github.com/FoxIO-LLC/ja4) — doğrulanmış IoC feed.
_KNOWN_BAD_JA4S: frozenset[str] = frozenset({
    # ── CobaltStrike (OpenSSL, TLS 1.2, cipher 0xC030) ──────────────────────
    "t120300_c030_5e2616a54c73",  # CS beacon default                  T1071.001
    "t120300_c030_52d195ce1d92",  # CS v4.9.1 beacon                   T1071.001
    # ── Sliver Agent (Go crypto/tls, TLS 1.3, cipher 0x1301) ────────────────
    "t130200_1301_a56c5b993250",  # Sliver HTTPS listener              T1071.001
})


def parse_ssl(row: dict) -> Optional[NormalizedLog]:
    sni = row.get("server_name") or ""
    validation = row.get("validation_status") or ""
    subject = row.get("subject") or ""
    ja3 = (row.get("ja3") or "").strip()
    ja3s = (row.get("ja3s") or "").strip()
    ja4 = (row.get("ja4") or "").strip()
    ja4s = (row.get("ja4s") or "").strip()

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
    bad_ja4  = ja4.lower()  in _KNOWN_BAD_JA4
    bad_ja3  = ja3.lower()  in _KNOWN_BAD_JA3
    bad_ja4s = ja4s.lower() in _KNOWN_BAD_JA4S

    # Çift eşleşme (istemci + sunucu fingerprint) → en yüksek güven
    double_match = bad_ja4 and bad_ja4s

    if double_match:
        severity = "critical"
        event_action = "tls_suspicious_fingerprint"
    elif bad_ja4 or bad_ja3:
        severity = "critical"
        event_action = "tls_suspicious_fingerprint"
    elif bad_ja4s:
        severity = "high"
        event_action = "tls_suspicious_ja4s"
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
    if ja4s and bad_ja4s:
        msg_parts.append(f"JA4S={ja4s[:12]}…[KNOWN_MALWARE_JA4S]")
    if double_match:
        msg_parts.append("[DOUBLE_FINGERPRINT]")
    if bad_ja3:
        msg_parts.append(f"JA3={ja3[:8]}…[KNOWN_MALWARE_JA3]")
    elif ja3 and not ja4:
        msg_parts.append(f"JA3={ja3[:8]}…")

    extra: dict = {}
    if ja4:
        extra["ja4"] = ja4
    if ja4s:
        extra["ja4s"] = ja4s
    if ja3:
        extra["ja3"] = ja3
    if ja3s:
        extra["ja3s"] = ja3s
    if double_match:
        extra["double_fingerprint"] = True

    tags = ["zeek", "ssl"]
    if bad_ja4:
        tags.append("ja4_malware")
    if bad_ja4s:
        tags.append("ja4s_malware")
    if bad_ja3:
        tags.append("ja3_malware")
    if double_match:
        tags.append("double_fingerprint")

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


def parse_weird(row: dict) -> Optional[NormalizedLog]:
    name = (row.get("name") or "").strip()
    if not name or name == "-":
        return None

    src_ip = row.get("id.orig_h")
    dst_ip = row.get("id.resp_h")

    if name in _IGNORE_WEIRDS and _is_private(src_ip) and _is_private(dst_ip):
        return None

    notice_raw = row.get("notice")
    if isinstance(notice_raw, str):
        is_notice = notice_raw.upper() in ("T", "TRUE", "1")
    else:
        is_notice = bool(notice_raw)

    severity = "critical" if is_notice else "warning"
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    event_action = f"zeek_weird_{slug}"

    addl = (row.get("addl") or "").strip()
    if addl == "-":
        addl = ""
    msg = f"Protocol anomaly [{name}]"
    if addl:
        msg += f": {addl}"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action=event_action,
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=_port(row.get("id.orig_p")),
        destination_port=_port(row.get("id.resp_p")),
        network_protocol=row.get("proto", "tcp"),
        message=msg,
        tags=["zeek", "weird", slug],
    )


def parse_dpd(row: dict) -> Optional[NormalizedLog]:
    analyzer = (row.get("analyzer") or "").strip()
    if not analyzer or analyzer == "-":
        return None

    resp_p = _port(row.get("id.resp_p"))
    failure_reason = (row.get("failure_reason") or "").strip()
    if failure_reason == "-":
        failure_reason = ""

    is_suspicious = (
        resp_p in _SUSPICIOUS_DPD_PORTS
        and analyzer.upper() in _SUSPICIOUS_DPD_ANALYZERS
    )
    severity = "critical" if is_suspicious else "warning"

    slug = re.sub(r"[^a-z0-9]+", "_", analyzer.lower()).strip("_")
    event_action = f"zeek_dpd_{slug}_failure"

    msg = f"DPD [{analyzer}] analyzer failure"
    if resp_p:
        msg += f" on port {resp_p}"
    if failure_reason:
        msg += f": {failure_reason[:120]}"

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
        destination_port=resp_p,
        network_protocol=(row.get("proto") or "tcp"),
        message=msg,
        tags=["zeek", "dpd", slug],
    )


def parse_files(row: dict) -> Optional[NormalizedLog]:
    sha256 = (row.get("sha256") or "").strip()
    sha1   = (row.get("sha1")   or "").strip()
    md5    = (row.get("md5")    or "").strip()

    if sha256 == "-": sha256 = ""
    if sha1   == "-": sha1   = ""
    if md5    == "-": md5    = ""

    if not (sha256 or sha1 or md5):
        return None

    try:
        missing_bytes = int(row.get("missing_bytes") or 0)
    except (ValueError, TypeError):
        missing_bytes = 0
    if missing_bytes > 0:
        return None

    mime_type = (row.get("mime_type") or "").strip()
    if mime_type == "-":
        mime_type = ""
    filename = (row.get("filename") or "").strip()
    if filename == "-":
        filename = ""

    local_orig_raw = row.get("local_orig")
    is_orig_raw    = row.get("is_orig")
    if isinstance(local_orig_raw, str):
        local_orig = local_orig_raw.upper() in ("T", "TRUE", "1")
    else:
        local_orig = bool(local_orig_raw)
    if isinstance(is_orig_raw, str):
        is_orig = is_orig_raw.upper() in ("T", "TRUE", "1")
    else:
        is_orig = bool(is_orig_raw)

    if not local_orig:
        return None

    direction = "outbound" if is_orig else "inbound"

    is_suspicious = mime_type in _SUSPICIOUS_MIME_TYPES
    if is_suspicious or direction == "outbound":
        severity = "critical"
    else:
        severity = "warning"

    event_action = f"zeek_file_{direction}_suspicious" if is_suspicious else f"zeek_file_{direction}"

    tx_hosts = row.get("tx_hosts") or []
    rx_hosts = row.get("rx_hosts") or []
    if isinstance(tx_hosts, str):
        tx_hosts = [tx_hosts] if tx_hosts not in ("-", "") else []
    if isinstance(rx_hosts, str):
        rx_hosts = [rx_hosts] if rx_hosts not in ("-", "") else []

    source_ip = tx_hosts[0] if tx_hosts else None
    dest_ip   = rx_hosts[0] if rx_hosts else None

    msg = f"File {direction}"
    if mime_type:
        msg += f" [{mime_type}]"
    if filename:
        msg += f" ({filename})"
    if sha256:
        msg += f" sha256={sha256[:16]}…"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action=event_action,
        source_ip=source_ip,
        destination_ip=dest_ip,
        network_protocol="tcp",
        message=msg,
        extra={
            "direction":  direction,
            "mime_type":  mime_type,
            "filename":   filename,
            "sha256":     sha256,
            "sha1":       sha1,
            "md5":        md5,
        },
        tags=["zeek", "files", direction] + (["suspicious_mime"] if is_suspicious else []),
    )
