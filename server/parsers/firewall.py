"""
NetGuard — Firewall Log Parser

Desteklenen formatlar:
  - pfSense filterlog (CSV tabanlı syslog)
  - Cisco ASA (%ASA-N-XXXXXX)
  - FortiGate (key=value çiftleri)

Her parser bir NormalizedLog üretir veya None döner (parse edilemezse).
"""

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from shared.models import LogCategory, LogSourceType, NormalizedLog

logger = logging.getLogger(__name__)


def _make_log(
    source_type: LogSourceType,
    source_host: str,
    event_type: str,
    severity: str,
    category: LogCategory,
    message: str,
    raw_content: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    tags: Optional[list] = None,
    extra: Optional[dict] = None,
) -> NormalizedLog:
    now = datetime.now(timezone.utc)
    return NormalizedLog(
        log_id      = str(uuid.uuid4()),
        raw_id      = str(uuid.uuid4()),
        source_type = source_type,
        source_host = source_host,
        timestamp   = now,
        severity    = severity,
        category    = category,
        event_type  = event_type,
        src_ip      = src_ip,
        dst_ip      = dst_ip,
        src_port    = src_port,
        dst_port    = dst_port,
        protocol    = protocol,
        message     = message,
        tags        = tags or [],
        extra       = extra or {},
    )


# ──────────────────────────────────────────────────────────────────
#  pfSense filterlog parser
#  Apr 24 10:00:01 pfsense filterlog: 5,,,123,em0,match,block,in,4,...
# ──────────────────────────────────────────────────────────────────

_PFSENSE_HOST_RE = re.compile(r'\w+\s+\d+\s+[\d:]+\s+(\S+)\s+filterlog:')
_PFSENSE_FIELDS_RE = re.compile(r'filterlog:\s+(.+)$')


def parse_pfsense(line: str) -> Optional[NormalizedLog]:
    fm = _PFSENSE_FIELDS_RE.search(line)
    if not fm:
        return None
    parts = fm.group(1).split(",")
    if len(parts) < 19:
        return None

    hm = _PFSENSE_HOST_RE.search(line)
    source_host = hm.group(1) if hm else "pfsense"

    try:
        action    = parts[6].lower()
        direction = parts[7].lower()
        protocol  = parts[16].lower()
        src_ip    = parts[18]
        dst_ip    = parts[19] if len(parts) > 19 else None
        src_port  = int(parts[20]) if len(parts) > 20 and parts[20].isdigit() else None
        dst_port  = int(parts[21]) if len(parts) > 21 and parts[21].isdigit() else None
    except (IndexError, ValueError):
        return None

    blocked   = action == "block"
    severity  = "warning" if blocked else "info"
    event_type = "fw_block" if blocked else "fw_allow"
    msg = (
        f"pfSense {action.upper()} {direction.upper()} "
        f"{protocol.upper()} {src_ip}:{src_port} → {dst_ip}:{dst_port}"
    )

    return _make_log(
        source_type = LogSourceType.PFSENSE,
        source_host = source_host,
        event_type  = event_type,
        severity    = severity,
        category    = LogCategory.NETWORK,
        message     = msg,
        raw_content = line,
        src_ip      = src_ip,
        dst_ip      = dst_ip,
        src_port    = src_port,
        dst_port    = dst_port,
        protocol    = protocol,
        tags        = [action, direction],
        extra       = {"action": action, "direction": direction, "interface": parts[4]},
    )


# ──────────────────────────────────────────────────────────────────
#  Cisco ASA parser
#  %ASA-2-106001: Inbound TCP connection denied from 1.2.3.4/80 ...
# ──────────────────────────────────────────────────────────────────

_ASA_HEADER_RE = re.compile(r'%ASA-(?P<level>\d)-(?P<code>\d+):\s*(?P<msg>.+)$')
_ASA_DENY_RE   = re.compile(
    r'(?:deni\w+).+?from\s+(?P<src>[\d.]+)/(?P<sport>\d+)\s+to\s+(?P<dst>[\d.]+)/(?P<dport>\d+)',
    re.IGNORECASE,
)
_ASA_PERMIT_RE = re.compile(
    r'(?:built|permitted).+?(?P<proto>TCP|UDP|ICMP).+?'
    r'(?:\S+:)?(?P<src>[\d.]+)/(?P<sport>\d+).+?(?:\S+:)?(?P<dst>[\d.]+)/(?P<dport>\d+)',
    re.IGNORECASE,
)
_ASA_HOST_RE   = re.compile(r'\w+\s+\d+\s+[\d:]+\s+(\S+)\s+%ASA')
_ASA_SEV_MAP   = {"1":"critical","2":"high","3":"warning","4":"info","5":"info","6":"info","7":"info"}


def parse_cisco_asa(line: str) -> Optional[NormalizedLog]:
    hdr = _ASA_HEADER_RE.search(line)
    if not hdr:
        return None

    level    = hdr.group("level")
    code     = hdr.group("code")
    msg_raw  = hdr.group("msg")
    severity = _ASA_SEV_MAP.get(level, "info")

    hm = _ASA_HOST_RE.search(line)
    source_host = hm.group(1) if hm else "cisco-asa"

    src_ip = dst_ip = None
    src_port = dst_port = None
    blocked = False

    dm = _ASA_DENY_RE.search(msg_raw)
    if dm:
        src_ip, src_port = dm.group("src"), int(dm.group("sport"))
        dst_ip, dst_port = dm.group("dst"), int(dm.group("dport"))
        blocked  = True
        severity = severity if severity in ("critical", "high") else "warning"
    else:
        pm = _ASA_PERMIT_RE.search(msg_raw)
        if pm:
            src_ip, src_port = pm.group("src"), int(pm.group("sport"))
            dst_ip, dst_port = pm.group("dst"), int(pm.group("dport"))

    return _make_log(
        source_type = LogSourceType.CISCO_ASA,
        source_host = source_host,
        event_type  = "fw_block" if blocked else "fw_allow",
        severity    = severity,
        category    = LogCategory.NETWORK,
        message     = f"ASA-{level}-{code}: {msg_raw}",
        raw_content = line,
        src_ip      = src_ip,
        dst_ip      = dst_ip,
        src_port    = src_port,
        dst_port    = dst_port,
        tags        = [f"asa_code:{code}", f"level:{level}"],
        extra       = {"asa_code": code, "asa_level": level},
    )


# ──────────────────────────────────────────────────────────────────
#  FortiGate parser  (key=value çiftleri)
#  type=traffic subtype=forward level=notice srcip=1.2.3.4 ...
# ──────────────────────────────────────────────────────────────────

_FORTI_KV_RE    = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
_FORTI_LEVEL_MAP = {
    "emergency":"critical","alert":"critical","critical":"critical",
    "error":"high","warning":"warning","notice":"info","information":"info","debug":"info",
}


def parse_fortigate(line: str) -> Optional[NormalizedLog]:
    if "type=traffic" not in line and "type=utm" not in line:
        return None
    kv = {k: v.strip('"') for k, v in _FORTI_KV_RE.findall(line)}
    if not kv:
        return None

    action   = kv.get("action", "").lower()
    src_ip   = kv.get("srcip")
    dst_ip   = kv.get("dstip")
    src_port = int(kv["srcport"]) if kv.get("srcport", "").isdigit() else None
    dst_port = int(kv["dstport"]) if kv.get("dstport", "").isdigit() else None
    proto_n  = kv.get("proto", "")
    proto    = {"6": "tcp", "17": "udp", "1": "icmp"}.get(proto_n, proto_n or "")
    severity = _FORTI_LEVEL_MAP.get(kv.get("level", "").lower(), "info")
    blocked  = action in ("deny", "drop", "block", "reset")
    if blocked and severity == "info":
        severity = "warning"

    msg = (
        f"FortiGate {action.upper()} "
        f"{proto.upper() or 'PKT'} "
        f"{src_ip}:{src_port} → {dst_ip}:{dst_port}"
    )

    return _make_log(
        source_type = LogSourceType.FORTIGATE,
        source_host = kv.get("devname", "fortigate"),
        event_type  = "fw_block" if blocked else "fw_allow",
        severity    = severity,
        category    = LogCategory.NETWORK,
        message     = msg,
        raw_content = line,
        src_ip      = src_ip,
        dst_ip      = dst_ip,
        src_port    = src_port,
        dst_port    = dst_port,
        protocol    = proto or None,
        tags        = [action, proto, f"policy:{kv.get('policyid','?')}"],
        extra       = {"action": action, "policy": kv.get("policyid"), "devname": kv.get("devname")},
    )


# ──────────────────────────────────────────────────────────────────
#  Otomatik tespit + parse
# ──────────────────────────────────────────────────────────────────

def detect_and_parse(line: str) -> Optional[NormalizedLog]:
    """Firewall log satırını otomatik tespit et ve parse et."""
    if "filterlog:" in line:
        return parse_pfsense(line)
    if "%ASA-" in line:
        return parse_cisco_asa(line)
    if "type=traffic" in line or "type=utm" in line:
        return parse_fortigate(line)
    return None
