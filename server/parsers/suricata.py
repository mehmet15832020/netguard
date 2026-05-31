"""
Suricata EVE JSON parsers.

Suricata'nın ürettiği EVE JSON log satırlarını NormalizedLog'a çevirir.
Her parser: dict (EVE JSON satırı) → NormalizedLog | None

Desteklenen event_type değerleri:
  alert, dns, http, tls, flow, smtp, fileinfo, ssh, anomaly
"""

import re
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

from shared.models import NormalizedLog, LogSourceType, LogCategory
from server.parsers.zeek import _KNOWN_BAD_JA3, _KNOWN_BAD_JA4

logger = logging.getLogger(__name__)

_OBSERVER = "suricata"

# Token separator: splits on any run of non-alphanumeric chars.
# Compiled once at module level — zero per-call allocation.
_ALNUM_SEP = re.compile(r"[^a-z0-9]+")

# Single-word attack-tool tokens only.  Multi-word patterns are intentionally
# excluded because token splitting cannot match them reliably, and they cause
# substring FPs (e.g. "nucleirenderer" would hit "nuclei" with plain `in`).
# "python-paramiko" is covered by the "paramiko" token after splitting.
_SUSPICIOUS_UA_PATTERNS: frozenset[str] = frozenset({
    "sqlmap", "nikto", "masscan", "metasploit", "hydra",
    "dirbuster", "gobuster", "feroxbuster", "havij",
    "acunetix", "nuclei", "ffuf", "wfuzz", "burpsuite",
    "nessus", "openvas", "appscan",
})

_OLD_TLS_VERSIONS: frozenset[str] = frozenset({
    "tlsv1", "tls 1.0", "tls1.0",
    "tlsv1.1", "tls 1.1", "tls1.1",
    "sslv3", "ssl 3.0", "ssl3",
    "sslv2", "ssl 2.0", "ssl2",
})

# Same single-word constraint: "paramiko" covers "python-paramiko" after split.
_SUSPICIOUS_SSH_CLIENTS: frozenset[str] = frozenset({
    "libssh", "paramiko", "nmap", "masscan",
})


def _is_suspicious_ua(ua) -> bool:
    """Return True for empty UA or UA whose tokens intersect known attack tools."""
    if not isinstance(ua, str):
        ua = str(ua) if ua is not None else ""
    ua = ua.strip()
    if not ua:
        return True
    tokens = set(_ALNUM_SEP.split(ua.lower()))
    return bool(tokens & _SUSPICIOUS_UA_PATTERNS)


def _is_old_tls_version(version) -> bool:
    if not isinstance(version, str):
        return False
    return version.lower().strip() in _OLD_TLS_VERSIONS


def _is_suspicious_ssh_client(sw) -> bool:
    if not isinstance(sw, str):
        return False
    sw = sw.strip()
    if not sw:
        return False
    tokens = set(_ALNUM_SEP.split(sw.lower()))
    return bool(tokens & _SUSPICIOUS_SSH_CLIENTS)


def _ts(val: str) -> datetime:
    try:
        return datetime.fromisoformat(val.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _port(val) -> Optional[int]:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _severity_from_priority(priority: int) -> str:
    if priority <= 1:
        return "critical"
    if priority <= 2:
        return "warning"
    return "info"


def _common(row: dict):
    ts    = _ts(row.get("timestamp", ""))
    src_ip   = row.get("src_ip")
    src_port = _port(row.get("src_port"))
    dst_ip   = row.get("dest_ip")
    dst_port = _port(row.get("dest_port"))
    proto    = (row.get("proto") or "").lower() or None
    return ts, src_ip, src_port, dst_ip, dst_port, proto


def parse_alert(row: dict) -> Optional[NormalizedLog]:
    alert = row.get("alert", {})
    if not alert:
        return None

    ts, src_ip, src_port, dst_ip, dst_port, proto = _common(row)
    sig      = alert.get("signature", "Suricata alert")
    category = alert.get("category", "")
    priority = int(alert.get("severity", 3))
    sid      = str(alert.get("signature_id", ""))
    action   = alert.get("action", "allowed")
    severity = _severity_from_priority(priority)

    tags = ["suricata", "ids_alert"]
    if category:
        tags.append(category.lower().replace(" ", "_"))
    if action == "blocked":
        tags.append("blocked")

    msg = f"Suricata [{sid}] {sig}"
    if category:
        msg += f" ({category})"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.SURICATA,
        observer_hostname=_OBSERVER,
        timestamp=ts,
        severity=severity,
        event_category=LogCategory.INTRUSION,
        event_action="suricata_alert",
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        network_protocol=proto,
        message=msg,
        tags=tags,
        extra={"sid": sid, "category": category, "action": action, "priority": priority},
    )


def parse_dns(row: dict) -> Optional[NormalizedLog]:
    dns = row.get("dns", {})
    if not dns:
        return None

    ts, src_ip, src_port, dst_ip, dst_port, proto = _common(row)
    rrname  = dns.get("rrname", "")
    rrtype  = dns.get("rrtype", "A")
    rcode   = dns.get("rcode", "")
    dtype   = dns.get("type", "query")

    indicators = []
    if rcode and rcode not in ("NOERROR", ""):
        indicators.append(rcode)

    msg = f"DNS {dtype} {rrname} ({rrtype})"
    if indicators:
        msg += " [" + "|".join(indicators) + "]"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.SURICATA,
        observer_hostname=_OBSERVER,
        timestamp=ts,
        severity="info",
        event_category=LogCategory.NETWORK,
        event_action="dns_query",
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        network_protocol=proto or "udp",
        message=msg,
        tags=["suricata", "dns"],
        extra={"rrtype": rrtype, "rcode": rcode, "dns_type": dtype},
    )


def parse_http(row: dict) -> Optional[NormalizedLog]:
    http = row.get("http", {})
    if not http:
        return None

    ts, src_ip, src_port, dst_ip, dst_port, proto = _common(row)
    hostname   = http.get("hostname", "")
    url        = http.get("url", "/")
    method     = http.get("http_method", "GET")
    status     = http.get("status", 0)
    _raw_ua   = http.get("http_user_agent")
    user_agent = _raw_ua if isinstance(_raw_ua, str) else (str(_raw_ua) if _raw_ua is not None else "")

    try:
        length = int(http.get("length") or 0)
    except (ValueError, TypeError):
        length = 0

    suspicious = _is_suspicious_ua(user_agent)
    event_action = "suricata_http_anomaly" if suspicious else "http_request"
    severity = "warning" if (suspicious or (isinstance(status, int) and status >= 400)) else "info"

    msg = f"HTTP {method} {hostname}{url} → {status}"
    if user_agent:
        msg += f" [{user_agent[:80]}]"
    if suspicious:
        msg += " [SUSPICIOUS-UA]"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.SURICATA,
        observer_hostname=_OBSERVER,
        timestamp=ts,
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action=event_action,
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        network_protocol=proto or "tcp",
        message=msg,
        tags=["suricata", "http"] + (["suspicious_ua"] if suspicious else []),
        extra={"method": method, "status": status, "length": length,
               "hostname": hostname, "user_agent": user_agent[:200]},
        network_bytes=length or None,
    )


def parse_tls(row: dict) -> Optional[NormalizedLog]:
    tls = row.get("tls", {})
    if not tls:
        return None

    ts, src_ip, src_port, dst_ip, dst_port, proto = _common(row)
    sni         = tls.get("sni", "")
    subject     = tls.get("subject", "")
    issuer      = tls.get("issuerdn", "")
    version     = tls.get("version", "")
    fingerprint = tls.get("fingerprint", "")

    # EVE JSON emits JA3 as flat string (`tls.ja3_hash`) by default (Suricata ≥7),
    # or as nested dict (`tls.ja3.hash`) when output-extended: yes is set.
    ja3_block = tls.get("ja3", {})
    ja3_hash  = (
        (tls.get("ja3_hash") or "").lower().strip()
        or ((ja3_block.get("hash") or "").lower().strip() if isinstance(ja3_block, dict) else "")
    )
    ja4_hash = (tls.get("ja4") or "").lower().strip()

    bad_ja3 = bool(ja3_hash and ja3_hash in _KNOWN_BAD_JA3)
    bad_ja4 = bool(ja4_hash and ja4_hash in _KNOWN_BAD_JA4)

    indicators = []
    if "self-signed" in issuer.lower() or (issuer and issuer == subject):
        indicators.append("SELF-SIGNED")
    if bad_ja4:
        indicators.append("KNOWN_MALWARE_JA4")
    if bad_ja3:
        indicators.append("KNOWN_MALWARE_JA3")

    is_old_version = _is_old_tls_version(version)
    if is_old_version:
        indicators.append("OLD-TLS-VERSION")

    is_self_signed = "SELF-SIGNED" in indicators

    # Priority: bad fingerprint > TLS anomaly > normal
    if bad_ja3 or bad_ja4:
        event_action = "tls_suspicious_fingerprint"
    elif is_self_signed or is_old_version:
        event_action = "suricata_tls_anomaly"
    else:
        event_action = "ssl_connection"

    # JA4 primary (per project G6 policy): bad JA4 → critical; bad JA3 only → warning
    severity = "critical" if bad_ja4 else ("warning" if (bad_ja3 or indicators) else "info")

    msg_parts = [f"SSL/TLS {sni or dst_ip or '?'}"]
    if version:
        msg_parts.append(version)
    if ja4_hash:
        msg_parts.append(f"JA4={ja4_hash}")
    if ja3_hash:
        msg_parts.append(f"JA3={ja3_hash}")
    if indicators:
        msg_parts.extend(f"[{i}]" for i in indicators)
    msg = " ".join(msg_parts)

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.SURICATA,
        observer_hostname=_OBSERVER,
        timestamp=ts,
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action=event_action,
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        network_protocol=proto or "tcp",
        message=msg,
        tags=(["suricata", "tls"]
              + (["suspicious_fingerprint"] if event_action == "tls_suspicious_fingerprint" else [])
              + (["tls_anomaly"] if event_action == "suricata_tls_anomaly" else [])),
        extra={"sni": sni, "ja3": ja3_hash, "ja4": ja4_hash, "version": version},
    )


def parse_flow(row: dict) -> Optional[NormalizedLog]:
    flow = row.get("flow", {})
    if not flow:
        return None

    ts, src_ip, src_port, dst_ip, dst_port, proto = _common(row)
    state    = flow.get("state", "")
    reason   = flow.get("reason", "")
    bytes_ts = int(flow.get("bytes_toserver", 0) or 0)
    bytes_tc = int(flow.get("bytes_toclient", 0) or 0)
    pkts_ts  = int(flow.get("pkts_toserver", 0) or 0)
    pkts_tc  = int(flow.get("pkts_toclient", 0) or 0)
    app_proto = row.get("app_proto", "")

    msg = f"Flow {proto or '?'} {src_ip}:{src_port} → {dst_ip}:{dst_port} [{state}]"
    if app_proto:
        msg += f" app={app_proto}"
    msg += f" bytes={bytes_ts + bytes_tc}"

    total_bytes = bytes_ts + bytes_tc

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.SURICATA,
        observer_hostname=_OBSERVER,
        timestamp=ts,
        severity="info",
        event_category=LogCategory.NETWORK,
        event_action="network_flow",
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        network_protocol=proto,
        message=msg,
        tags=["suricata", "flow"],
        extra={"bytes_toserver": bytes_ts, "bytes_toclient": bytes_tc,
               "pkts_toserver": pkts_ts, "pkts_toclient": pkts_tc,
               "state": state, "reason": reason, "app_proto": app_proto},
        network_bytes=total_bytes or None,
    )


def parse_smtp(row: dict) -> Optional[NormalizedLog]:
    smtp = row.get("smtp", {})
    if not smtp:
        return None

    ts, src_ip, src_port, dst_ip, dst_port, proto = _common(row)
    mail_from = smtp.get("mail_from", "")
    rcpt_to   = smtp.get("rcpt_to", [])
    helo      = smtp.get("helo", "")

    rcpt_str = ", ".join(rcpt_to) if isinstance(rcpt_to, list) else str(rcpt_to)
    msg = f"SMTP from={mail_from} to={rcpt_str}"
    if helo:
        msg += f" helo={helo}"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.SURICATA,
        observer_hostname=_OBSERVER,
        timestamp=ts,
        severity="info",
        event_category=LogCategory.NETWORK,
        event_action="smtp_session",
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        network_protocol=proto or "tcp",
        message=msg,
        tags=["suricata", "smtp"],
        extra={"mail_from": mail_from, "rcpt_to": rcpt_to, "helo": helo},
    )


def parse_fileinfo(row: dict) -> Optional[NormalizedLog]:
    fi = row.get("fileinfo", {})
    if not fi:
        return None

    ts, src_ip, src_port, dst_ip, dst_port, proto = _common(row)
    filename = fi.get("filename", "")
    magic    = fi.get("magic", "")
    md5      = fi.get("md5", "")
    state    = fi.get("state", "")

    try:
        size = int(fi.get("size") or 0)
    except (ValueError, TypeError):
        size = 0

    severity = "warning" if state in ("TRUNCATED", "ERROR") else "info"
    msg = f"File {filename or '?'} size={size}"
    if magic:
        msg += f" type={magic[:50]}"
    if md5:
        msg += f" md5={md5}"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.SURICATA,
        observer_hostname=_OBSERVER,
        timestamp=ts,
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action="file_download",
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        network_protocol=proto,
        message=msg,
        tags=["suricata", "fileinfo"],
        extra={"filename": filename, "magic": magic, "md5": md5, "size": size, "state": state},
        network_bytes=size or None,
    )


def parse_ssh(row: dict) -> Optional[NormalizedLog]:
    ssh = row.get("ssh", {})
    if not ssh:
        return None

    ts, src_ip, src_port, dst_ip, dst_port, proto = _common(row)
    client  = ssh.get("client", {})
    server  = ssh.get("server", {})
    c_sw    = client.get("software_version", "")
    c_proto = client.get("proto_version", "")
    s_sw    = server.get("software_version", "")

    suspicious = _is_suspicious_ssh_client(c_sw)
    event_action = "suricata_ssh_anomaly" if suspicious else "ssh_attempt"
    severity = "warning" if suspicious else "info"

    msg = f"SSH client={c_sw or '?'}"
    if c_proto:
        msg += f" proto={c_proto}"
    if s_sw:
        msg += f" server={s_sw}"
    if suspicious:
        msg += " [SUSPICIOUS-CLIENT]"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.SURICATA,
        observer_hostname=_OBSERVER,
        timestamp=ts,
        severity=severity,
        event_category=LogCategory.AUTHENTICATION,
        event_action=event_action,
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        network_protocol=proto or "tcp",
        message=msg,
        tags=["suricata", "ssh"] + (["suspicious_client"] if suspicious else []),
        extra={"client_sw": c_sw, "proto_version": c_proto, "server_sw": s_sw},
    )


def parse_anomaly(row: dict) -> Optional[NormalizedLog]:
    anomaly = row.get("anomaly", {})
    if not anomaly:
        return None

    ts, src_ip, src_port, dst_ip, dst_port, proto = _common(row)
    atype = anomaly.get("type", "")
    event = anomaly.get("event", "")
    layer = anomaly.get("layer", "")

    msg = f"Suricata anomaly type={atype} event={event}"
    if layer:
        msg += f" layer={layer}"

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.SURICATA,
        observer_hostname=_OBSERVER,
        timestamp=ts,
        severity="warning",
        event_category=LogCategory.INTRUSION,
        event_action="suricata_anomaly",
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        network_protocol=proto,
        message=msg,
        tags=["suricata", "anomaly"],
        extra={"type": atype, "event": event, "layer": layer},
    )


_PARSERS: dict[str, callable] = {
    "alert":    parse_alert,
    "dns":      parse_dns,
    "http":     parse_http,
    "tls":      parse_tls,
    "flow":     parse_flow,
    "smtp":     parse_smtp,
    "fileinfo": parse_fileinfo,
    "ssh":      parse_ssh,
    "anomaly":  parse_anomaly,
}


def parse_eve_line(row: dict) -> Optional[NormalizedLog]:
    """EVE JSON satırını event_type'a göre ilgili parser'a yönlendir."""
    event_type = row.get("event_type", "")
    parser = _PARSERS.get(event_type)
    if parser is None:
        return None
    try:
        return parser(row)
    except Exception as exc:
        logger.debug("Suricata EVE parse hatası [%s]: %s", event_type, exc)
        return None
