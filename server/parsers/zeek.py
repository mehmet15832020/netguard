"""
Zeek JSON log parsers.

Desteklenen log türleri: dns, http, conn, ssl, ssh, notice, x509, smtp, ftp,
                         weird, dpd, files, rdp, kerberos, smb_files, dce_rpc,
                         dhcp, tunnel, pe, smb_mapping, software
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
        community_id=row.get("community_id"),
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
        community_id=row.get("community_id"),
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
        community_id=row.get("community_id"),
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
        community_id=row.get("community_id"),
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
        community_id=row.get("community_id"),
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
        community_id=row.get("community_id"),
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
        community_id=row.get("community_id"),
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
        community_id=row.get("community_id"),
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
        community_id=row.get("community_id"),
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
        community_id=row.get("community_id"),
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
        community_id=row.get("community_id"),
    )


_RDP_SUSPICIOUS_CLIENTS: frozenset[str] = frozenset({
    "rdp-exploit", "metasploit", "scanner", "nmap", "masscan",
    "impacket", "hydra", "medusa", "crowbar",
})

_KERBEROS_WEAK_CIPHERS: frozenset[str] = frozenset({
    "rc4-hmac", "rc4-hmac-exp", "des-cbc-crc", "des-cbc-md5",
    "rc4-hmac-old", "rc4-hmac-old-exp",
})

_SMB_ADMIN_SHARES: frozenset[str] = frozenset({
    "ADMIN$", "C$", "D$", "E$", "IPC$",
})

_SMB_SUSPICIOUS_FILES: frozenset[str] = frozenset({
    "psexec.exe", "psexesvc.exe", "plink.exe", "mimikatz.exe",
    "procdump.exe", "procdump64.exe", "wce.exe", "fgdump.exe",
    "pwdump.exe", "gsecdump.exe", "meterpreter", "beacon",
})

_SMB_RECON_SHARES: frozenset[str] = frozenset({
    "SYSVOL", "NETLOGON",
})

_DCE_CRITICAL: dict[tuple[str, str], tuple[str, str]] = {
    ("drsuapi",      "dsgetncchanges"):     ("zeek_dce_rpc_dcsync",   "critical"),
    ("svcctl",       "createservicew"):     ("zeek_dce_rpc_psexec",   "critical"),
    ("svcctl",       "startservicew"):      ("zeek_dce_rpc_psexec",   "critical"),
    ("svcctl",       "createservicewow64w"):("zeek_dce_rpc_psexec",   "critical"),
    ("iwbemservices","execmethod"):         ("zeek_dce_rpc_wmi",      "high"),
    ("iwbemservices","execmethodasync"):    ("zeek_dce_rpc_wmi",      "high"),
    ("atsvc",        "schrpcregistertask"): ("zeek_dce_rpc_task",     "high"),
    ("atsvc",        "schrpcenabletask"):   ("zeek_dce_rpc_task",     "high"),
    ("atsvc",        "schrpcrun"):          ("zeek_dce_rpc_task",     "high"),
    ("itaskschedulerservice", "registertask"): ("zeek_dce_rpc_task",  "high"),
    ("winreg",       "openkey"):            ("zeek_dce_rpc_registry", "high"),
    ("winreg",       "setvalue"):           ("zeek_dce_rpc_registry", "high"),
    ("samr",         "samrenumerateuserindomain"): ("zeek_dce_rpc_samr_enum", "warning"),
    ("samr",         "samlookupnamesindomain"):    ("zeek_dce_rpc_samr_enum", "warning"),
    ("samr",         "samconnect5"):               ("zeek_dce_rpc_samr_enum", "warning"),
    ("lsarpc",       "lsarqueryinformationpolicy"):("zeek_dce_rpc_policy",    "info"),
    ("lsarpc",       "lsarenumerateprivileges"):   ("zeek_dce_rpc_policy",    "info"),
}


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
        community_id=row.get("community_id"),
    )


def parse_rdp(row: dict) -> Optional[NormalizedLog]:
    result = (row.get("result") or "").strip()
    if result == "-":
        result = ""

    try:
        cert_count = int(row.get("cert_count") or 0)
    except (ValueError, TypeError):
        cert_count = 0

    try:
        client_build = int(row.get("client_build") or 0)
    except (ValueError, TypeError):
        client_build = 0

    client_name = (row.get("client_name") or "").strip()
    if client_name == "-":
        client_name = ""

    security_proto = (row.get("security_protocol") or "").strip()
    if security_proto == "-":
        security_proto = ""

    is_success = bool(result) and cert_count > 0
    client_lower = client_name.lower()
    is_suspicious_client = any(s in client_lower for s in _RDP_SUSPICIOUS_CLIENTS)

    if is_suspicious_client:
        event_action = "zeek_rdp_suspicious_client"
        severity = "critical"
    elif not is_success and cert_count == 0 and (result or security_proto):
        event_action = "zeek_rdp_no_cert"
        severity = "critical"
    elif not is_success:
        event_action = "zeek_rdp_failure"
        severity = "warning"
    else:
        event_action = "zeek_rdp_success"
        severity = "info"

    msg = f"RDP {event_action.replace('zeek_rdp_', '')}"
    if client_name:
        msg += f" client={client_name}"
    if security_proto:
        msg += f" proto={security_proto}"
    if cert_count == 0 and (result or security_proto):
        msg += " [NO_CERT]"

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
        message=msg,
        extra={
            "result": result,
            "cert_count": cert_count,
            "client_build": client_build,
            "client_name": client_name,
            "security_protocol": security_proto,
        },
        tags=["zeek", "rdp"] + (["no_cert"] if cert_count == 0 else []),
        community_id=row.get("community_id"),
    )


def parse_kerberos(row: dict) -> Optional[NormalizedLog]:
    request_type = (row.get("request_type") or "").strip()
    if not request_type or request_type == "-":
        return None

    client = (row.get("client") or "").strip()
    if client == "-":
        client = ""
    service = (row.get("service") or "").strip()
    if service == "-":
        service = ""

    success_raw = row.get("success")
    if isinstance(success_raw, str):
        success = success_raw.upper() in ("T", "TRUE", "1")
    else:
        success = bool(success_raw)

    cipher = (row.get("cipher") or "").strip().lower()
    if cipher == "-":
        cipher = ""

    error_msg = (row.get("error_msg") or "").strip()
    if error_msg == "-":
        error_msg = ""

    def _bool_field(key: str) -> bool:
        v = row.get(key)
        if isinstance(v, str):
            return v.upper() in ("T", "TRUE", "1")
        return bool(v)

    forwardable = _bool_field("forwardable")
    renewable   = _bool_field("renewable")

    try:
        from_ts  = float(row.get("from")  or 0)
        till_ts  = float(row.get("till")  or 0)
        ticket_duration = int(till_ts - from_ts) if till_ts > from_ts else 0
    except (ValueError, TypeError):
        ticket_duration = 0

    is_rc4 = cipher in _KERBEROS_WEAK_CIPHERS
    tags   = ["zeek", "kerberos"]

    if request_type == "TGS" and is_rc4 and success:
        event_action = "zeek_kerberos_tgs_rc4"
        severity     = "high"
        tags        += ["kerberoasting", "rc4"]

    elif request_type == "AS" and not success and "PREAUTH" in error_msg.upper():
        event_action = "zeek_kerberos_as_nopreauth"
        severity     = "high"
        tags        += ["as_rep_roasting"]

    elif forwardable and renewable and ticket_duration > 604800:
        event_action = "zeek_kerberos_golden_ticket"
        severity     = "critical"
        tags        += ["golden_ticket"]

    elif request_type == "TGS" and is_rc4:
        event_action = "zeek_kerberos_rc4_downgrade"
        severity     = "warning"
        tags        += ["rc4_downgrade"]

    elif not success:
        event_action = "zeek_kerberos_failure"
        severity     = "warning"
        tags        += ["failure"]

    else:
        event_action = f"zeek_kerberos_{request_type.lower()}"
        severity     = "info"

    msg = f"Kerberos {request_type}"
    if client:
        msg += f" client={client}"
    if service:
        msg += f" service={service}"
    if cipher:
        msg += f" cipher={cipher}"
    if not success and error_msg:
        msg += f" error={error_msg}"
    if ticket_duration > 604800:
        msg += f" duration={ticket_duration}s [SUSPICIOUS_LONG]"

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
        message=msg,
        extra={
            "request_type":      request_type,
            "client":            client,
            "service":           service,
            "success":           success,
            "cipher":            cipher,
            "error_msg":         error_msg,
            "forwardable":       forwardable,
            "renewable":         renewable,
            "ticket_duration_s": ticket_duration,
        },
        tags=tags,
        community_id=row.get("community_id"),
    )


def parse_smb_files(row: dict) -> Optional[NormalizedLog]:
    action = (row.get("action") or "").strip()
    if not action or action == "-":
        return None

    path = (row.get("path") or "").strip()
    if path == "-":
        path = ""
    name = (row.get("name") or "").strip()
    if name == "-":
        name = ""

    if not path and not name:
        return None

    try:
        file_size = int(row.get("size") or 0)
    except (ValueError, TypeError):
        file_size = 0

    path_upper = path.upper()
    name_lower = name.lower()

    is_admin_share  = any(f"\\{s}" in path_upper or path_upper.endswith(s)
                         for s in _SMB_ADMIN_SHARES)
    is_recon_share  = any(s in path_upper for s in _SMB_RECON_SHARES)
    is_suspicious   = any(s in name_lower for s in _SMB_SUSPICIOUS_FILES)

    action_key = action.replace("SMB::", "").upper()

    if action_key == "FILE_WRITE":
        if is_admin_share or is_suspicious:
            event_action = "zeek_smb_admin_share" if is_admin_share else "zeek_smb_suspicious_file"
            severity = "critical"
            tags = ["zeek", "smb", "lateral_movement"]
        else:
            event_action = "zeek_smb_write"
            severity = "warning"
            tags = ["zeek", "smb"]
    elif action_key == "FILE_DELETE":
        event_action = "zeek_smb_delete"
        severity = "high"
        tags = ["zeek", "smb", "cover_tracks"]
    elif action_key == "FILE_RENAME":
        event_action = "zeek_smb_rename"
        severity = "warning"
        tags = ["zeek", "smb"]
    elif action_key == "FILE_OPEN":
        if is_recon_share:
            event_action = "zeek_smb_recon"
            severity = "warning"
            tags = ["zeek", "smb", "recon"]
        else:
            event_action = "zeek_smb_open"
            severity = "info"
            tags = ["zeek", "smb"]
    else:
        event_action = "zeek_smb_operation"
        severity = "info"
        tags = ["zeek", "smb"]

    msg = f"SMB {action_key}"
    if name:
        msg += f" file={name}"
    if path:
        msg += f" path={path}"
    if is_admin_share:
        msg += " [ADMIN_SHARE]"
    if is_suspicious:
        msg += " [SUSPICIOUS_FILE]"
    if is_recon_share:
        msg += " [RECON]"

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
        message=msg,
        extra={
            "action":         action,
            "path":           path,
            "name":           name,
            "size":           file_size,
            "is_admin_share": is_admin_share,
        },
        tags=tags,
        community_id=row.get("community_id"),
    )


def parse_dce_rpc(row: dict) -> Optional[NormalizedLog]:
    endpoint  = (row.get("endpoint")  or "").strip()
    operation = (row.get("operation") or "").strip()

    if not endpoint or endpoint == "-" or not operation or operation == "-":
        return None

    named_pipe = (row.get("named_pipe") or "").strip()
    if named_pipe == "-":
        named_pipe = ""

    try:
        rtt = float(row.get("rtt") or 0)
    except (ValueError, TypeError):
        rtt = 0.0

    key = (endpoint.lower(), operation.lower())
    if key in _DCE_CRITICAL:
        event_action, severity = _DCE_CRITICAL[key]
        tags = ["zeek", "dce_rpc", event_action.replace("zeek_dce_rpc_", "")]
    else:
        event_action = "zeek_dce_rpc_operation"
        severity     = "info"
        tags         = ["zeek", "dce_rpc"]

    msg = f"DCE-RPC {endpoint}::{operation}"
    if named_pipe:
        msg += f" pipe={named_pipe}"
    if rtt > 0:
        msg += f" rtt={rtt:.0f}ms"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.INTRUSION,
        event_action=event_action,
        source_ip=row.get("id.orig_h"),
        destination_ip=row.get("id.resp_h"),
        source_port=_port(row.get("id.orig_p")),
        destination_port=_port(row.get("id.resp_p")),
        network_protocol="tcp",
        message=msg,
        extra={
            "endpoint":    endpoint,
            "operation":   operation,
            "named_pipe":  named_pipe,
            "rtt":         rtt,
        },
        tags=tags,
        community_id=row.get("community_id"),
    )


def parse_dhcp(row: dict) -> Optional[NormalizedLog]:
    """
    dhcp.log — C1. Zeek şeması: ts, uids, client_addr, server_addr, mac,
    host_name, client_fqdn, domain, requested_addr, assigned_addr,
    lease_time, msg_types (zeek.org/en/current/logs/dhcp.html, doğrulandı).

    IP→MAC→hostname eşlemesi sağlar — saldırı triage'ında "bu IP hangi
    cihaz?" sorusunu yanıtlar (NIST SP 800-94 §3.3).
    """
    mac = (row.get("mac") or "").strip()
    assigned_addr = row.get("assigned_addr") or ""
    client_addr = row.get("client_addr") or ""
    assigned_ip = assigned_addr if assigned_addr not in ("", "-") else client_addr
    if not mac or mac == "-" or not assigned_ip or assigned_ip == "-":
        return None

    host_name = (row.get("host_name") or "").strip()
    if host_name == "-":
        host_name = ""

    try:
        lease_time = float(row.get("lease_time") or 0)
    except (ValueError, TypeError):
        lease_time = 0.0

    msg_types = row.get("msg_types") or []
    if isinstance(msg_types, str):
        msg_types = [m.strip() for m in msg_types.split(",") if m.strip()]

    severity = "warning" if "NAK" in msg_types else "info"

    msg = f"DHCP lease: {assigned_ip} → {mac}"
    if host_name:
        msg += f" ({host_name})"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action="dhcp_lease",
        source_ip=assigned_ip,
        destination_ip=row.get("server_addr"),
        message=msg,
        extra={
            "mac":         mac,
            "host_name":   host_name,
            "lease_time":  lease_time,
            "msg_types":   msg_types,
        },
        tags=["zeek", "dhcp"],
    )


# Tunnel tipleri normalde nadir kullanılır — GRE/AYIYA/Teredo/SOCKS C2/exfil
# için sıkça istismar edilir (MITRE T1572). IP-in-IP/VXLAN/GTPv1 daha çok
# meşru altyapı amaçlı (IPv6 geçişi, datacenter overlay, mobil operatör).
_HIGH_RISK_TUNNEL_TYPES: frozenset[str] = frozenset({
    "GRE", "AYIYA", "TEREDO", "SOCKS", "HTTP",
})


def parse_tunnel(row: dict) -> Optional[NormalizedLog]:
    """
    tunnel.log — C2. Zeek şeması: ts, uid, id.orig_h/p, id.resp_h/p,
    tunnel_type, action (zeek.org/en/current/logs/tunnel.html, doğrulandı).

    tunnel_type: Tunnel::GRE | Tunnel::IP | Tunnel::TEREDO | Tunnel::AYIYA |
                 Tunnel::SOCKS | Tunnel::HTTP | Tunnel::VXLAN | Tunnel::GTPv1
    action: Tunnel::DISCOVER | Tunnel::CLOSE | Tunnel::EXPIRE

    Protokol tünelleme — saldırganlar evasion/exfil için kullanır
    (MITRE ATT&CK T1572).
    """
    tunnel_type = (row.get("tunnel_type") or "").strip()
    if not tunnel_type or tunnel_type == "-":
        return None
    tunnel_type = tunnel_type.removeprefix("Tunnel::")

    action = (row.get("action") or "").strip()
    action = action.removeprefix("Tunnel::") if action and action != "-" else "UNKNOWN"

    if action == "DISCOVER":
        severity = "warning" if tunnel_type.upper() in _HIGH_RISK_TUNNEL_TYPES else "info"
    else:
        severity = "info"  # CLOSE/EXPIRE — yaşam döngüsü bilgisi, yeni tünel değil

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action="network_tunnel_detected",
        source_ip=row.get("id.orig_h"),
        destination_ip=row.get("id.resp_h"),
        source_port=_port(row.get("id.orig_p")),
        destination_port=_port(row.get("id.resp_p")),
        message=f"Tunnel {action}: {tunnel_type} {row.get('id.orig_h')} → {row.get('id.resp_h')}",
        extra={"tunnel_type": tunnel_type, "action": action},
        tags=["zeek", "tunnel", tunnel_type.lower()],
    )


# PE section adları — meşru derleyici/linker çıktısında görülen standart set.
# Bilinmeyen/garip section adı, paketleyici (UPX vb.) veya custom packer
# kullanıldığının klasik göstergesidir (MITRE T1027 — Obfuscated Files).
_STANDARD_PE_SECTIONS: frozenset[str] = frozenset({
    ".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata",
    ".idata", ".edata", ".bss", ".tls", ".00cfg", ".didat", ".debug",
})


def _bool_field(val) -> bool:
    if isinstance(val, str):
        return val.upper() in ("T", "TRUE", "1")
    return bool(val)


def parse_pe(row: dict) -> Optional[NormalizedLog]:
    """
    pe.log — C3. Zeek şeması: ts, id (fuid), machine, compile_ts, os,
    subsystem, is_exe, is_64bit, uses_aslr, uses_dep, uses_code_integrity,
    uses_seh, has_import_table, has_export_table, has_cert_table,
    has_debug_data, section_names (zeek.org/en/current/logs/pe.html, doğrulandı).

    Not: pe.log IP taşımaz (files framework'ü dosya UID'siyle çalışır) —
    bağlam için files.log'daki aynı fuid ile çapraz sorgulanmalı (extra.fuid).
    Hash bilgisi de pe.log'da değil files.log'da (parse_files zaten kapsıyor).

    Ağdan geçen EXE/DLL meta verisi — malware analizi ve eski/paketlenmiş
    binary tespiti sağlar (Security Onion/Malcolm önceliği).
    """
    fuid = (row.get("id") or "").strip()
    if not fuid or fuid == "-":
        return None

    machine = (row.get("machine") or "").strip()
    os_name = (row.get("os") or "").strip()
    subsystem = (row.get("subsystem") or "").strip()

    is_exe = _bool_field(row.get("is_exe"))
    is_64bit = _bool_field(row.get("is_64bit"))
    uses_aslr = _bool_field(row.get("uses_aslr"))
    uses_dep = _bool_field(row.get("uses_dep"))
    has_cert_table = _bool_field(row.get("has_cert_table"))

    section_names = row.get("section_names") or []
    if isinstance(section_names, str):
        section_names = [s.strip() for s in section_names.split(",") if s.strip()]
    has_nonstandard_sections = any(
        s.lower() not in _STANDARD_PE_SECTIONS for s in section_names
    )

    is_unsigned = not has_cert_table
    severity = "warning" if (is_unsigned and has_nonstandard_sections) else "info"

    msg = f"PE metadata: {'EXE' if is_exe else 'DLL/OBJ'}"
    if machine:
        msg += f" {machine}"
    msg += f" {'64-bit' if is_64bit else '32-bit'}"
    if is_unsigned and has_nonstandard_sections:
        msg += " [UNSIGNED+PACKED_INDICATOR]"
    elif is_unsigned:
        msg += " [UNSIGNED]"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action="pe_metadata",
        message=msg,
        extra={
            "fuid": fuid,
            "machine": machine,
            "os": os_name,
            "subsystem": subsystem,
            "is_exe": is_exe,
            "is_64bit": is_64bit,
            "uses_aslr": uses_aslr,
            "uses_dep": uses_dep,
            "has_cert_table": has_cert_table,
            "section_names": section_names,
            "has_nonstandard_sections": has_nonstandard_sections,
        },
        tags=["zeek", "pe"] + (["unsigned"] if is_unsigned else []) + (["packed_indicator"] if has_nonstandard_sections else []),
    )


def parse_smb_mapping(row: dict) -> Optional[NormalizedLog]:
    """
    smb_mapping.log — C4. Zeek şeması: ts, uid, id.orig/resp_h/p, path,
    service, native_file_system, share_type (zeek.org §SMB Logs, doğrulandı).

    parse_smb_files() sadece dosya WRITE/DELETE/OPEN olduğunda admin share
    tespiti yapıyordu — bu fonksiyon paylaşıma *bağlanma* (tree-connect)
    anının kendisini yakalar. Saldırgan `net use \\\\host\\C$` yaptığında
    henüz dosya işlemi olmasa bile burada görünür — daha erken sinyal
    (MITRE ATT&CK T1021.002 — SMB/Windows Admin Shares).
    """
    path = (row.get("path") or "").strip()
    if not path or path == "-":
        return None

    service = (row.get("service") or "").strip()
    if service == "-":
        service = ""
    share_type = (row.get("share_type") or "").strip()
    if share_type == "-":
        share_type = ""
    native_fs = (row.get("native_file_system") or "").strip()
    if native_fs == "-":
        native_fs = ""

    path_upper = path.upper()
    is_admin_share = any(f"\\{s}" in path_upper or path_upper.endswith(s) for s in _SMB_ADMIN_SHARES)
    is_ipc = "IPC$" in path_upper

    if is_admin_share:
        event_action = "zeek_smb_admin_share_mapped"
        severity = "warning"
        tags = ["zeek", "smb_mapping", "lateral_movement"]
    else:
        event_action = "zeek_smb_share_mapped"
        severity = "info"
        tags = ["zeek", "smb_mapping"]

    msg = f"SMB share mapped: {path}"
    if service:
        msg += f" [{service}]"
    if is_admin_share:
        msg += " [ADMIN_SHARE]"
    if is_ipc:
        msg += " [IPC — null session/DCE-RPC riski]"

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
        message=msg,
        extra={
            "path": path,
            "service": service,
            "share_type": share_type,
            "native_file_system": native_fs,
            "is_admin_share": is_admin_share,
            "is_ipc": is_ipc,
        },
        tags=tags,
        community_id=row.get("community_id"),
    )


def _format_software_version(row: dict) -> str:
    """version.major/minor/minor2/minor3/addl dotted alanlarından versiyon string'i oluşturur."""
    parts = []
    for key in ("version.major", "version.minor", "version.minor2", "version.minor3"):
        val = row.get(key)
        if val is None or val == "" or val == "-":
            break
        parts.append(str(val))
    numeric = ".".join(parts)

    addl = row.get("version.addl")
    if addl and addl != "-":
        numeric = f"{numeric}{addl}" if numeric else str(addl)
    if numeric:
        return numeric

    unparsed = row.get("unparsed_version")
    if unparsed and unparsed != "-":
        return str(unparsed)
    return ""


def parse_software(row: dict) -> Optional[NormalizedLog]:
    """
    software.log — C5. Zeek şeması: ts, host, software_type, name,
    version.major/minor/minor2/minor3/addl, unparsed_version
    (zeek.org §known-and-software.html, doğrulandı).

    Pasif yazılım/versiyon parmak izi (User-Agent, Server header, SSH banner
    vb.) — eski/savunmasız sistemleri görünür kılar (NIST SP 800-94 §4.1).
    Server tarafında asset_baselines.detected_software'a eklenir
    (bkz. zeek_collector.py post-save hook — parser saf/DB'siz kalır).
    """
    host = row.get("host")
    if not host or host == "-":
        return None

    name = (row.get("name") or "").strip()
    if not name or name == "-":
        return None

    software_type = (row.get("software_type") or "").strip()
    if not software_type or software_type == "-":
        software_type = "UNKNOWN"

    version = _format_software_version(row)

    msg = f"Software detected: {name}"
    if version:
        msg += f" {version}"
    msg += f" [{software_type}] on {host}"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.ZEEK,
        observer_hostname="zeek",
        timestamp=_ts(row["ts"]),
        severity="info",
        event_category=LogCategory.NETWORK,
        event_action="software_detected",
        source_ip=host,
        message=msg,
        extra={"software_type": software_type, "name": name, "version": version},
        tags=["zeek", "software"],
    )
