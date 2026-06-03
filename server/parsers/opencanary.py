"""
OpenCanary honeypot JSON parsers.

Thinkst OpenCanary logtype eşlemeleri:
  SSH=2000, FTP=2100, HTTP=3000, SMB=5000, MySQL=8001, MSSQL=9001,
  SNMP=13000, RDP=13001, Redis=16001, TFTP=6001, NTP=100, Telnet=23

Her honeypot bağlantısı = critical severity (false positive sıfır).
Kaynak: MITRE ATT&CK Engage, NIST SP 800-115
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Optional

from shared.models import NormalizedLog, LogSourceType, LogCategory

logger = logging.getLogger(__name__)

_LOGTYPE_TO_ACTION: dict[int, str] = {
    2000:  "honeypot_ssh",
    2100:  "honeypot_ftp",
    3000:  "honeypot_http",
    5000:  "honeypot_smb",
    8001:  "honeypot_mysql",
    9001:  "honeypot_mssql",
    13000: "honeypot_snmp",
    13001: "honeypot_rdp",
    16001: "honeypot_redis",
    6001:  "honeypot_tftp",
    100:   "honeypot_ntp",
    23:    "honeypot_telnet",
}

_LOGTYPE_TO_NAME: dict[int, str] = {
    2000:  "SSH",
    2100:  "FTP",
    3000:  "HTTP",
    5000:  "SMB",
    8001:  "MySQL",
    9001:  "MSSQL",
    13000: "SNMP",
    13001: "RDP",
    16001: "Redis",
    6001:  "TFTP",
    100:   "NTP",
    23:    "Telnet",
}

_LOGTYPE_TO_PROTOCOL: dict[int, str] = {
    2000:  "tcp",
    2100:  "tcp",
    3000:  "tcp",
    5000:  "tcp",
    8001:  "tcp",
    9001:  "tcp",
    13000: "udp",
    13001: "tcp",
    16001: "tcp",
    6001:  "udp",
    100:   "udp",
    23:    "tcp",
}

_LOGTYPE_TO_CATEGORY: dict[int, LogCategory] = {
    2000:  LogCategory.AUTHENTICATION,
    2100:  LogCategory.NETWORK,
    3000:  LogCategory.NETWORK,
    5000:  LogCategory.NETWORK,
    8001:  LogCategory.INTRUSION,
    9001:  LogCategory.INTRUSION,
    13000: LogCategory.NETWORK,
    13001: LogCategory.NETWORK,
    16001: LogCategory.INTRUSION,
    6001:  LogCategory.NETWORK,
    100:   LogCategory.NETWORK,
    23:    LogCategory.AUTHENTICATION,
}


def _parse_utc_time(ts_str: str) -> datetime:
    if not ts_str:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _extract_credentials(logdata: dict) -> tuple[Optional[str], Optional[str]]:
    username = None
    password = None
    for key, val in logdata.items():
        ku = key.upper()
        if username is None and ("USER" in ku or ku == "USER"):
            username = str(val) if val is not None else None
        if password is None and ("PASS" in ku or "CRED" in ku):
            password = str(val) if val is not None else None
    return username, password


def parse_opencanary_line(row: dict) -> Optional[NormalizedLog]:
    """
    OpenCanary JSON satırını NormalizedLog'a çevirir.
    Her honeypot bağlantısı = critical (iç ağda meşru trafik olmaz).
    """
    try:
        logtype = int(row.get("logtype") or 0)
    except (ValueError, TypeError):
        return None

    if logtype not in _LOGTYPE_TO_ACTION:
        return None

    src_ip  = row.get("src_host")
    dst_ip  = row.get("dst_host")
    if not src_ip or not dst_ip:
        return None

    try:
        src_port = int(row.get("src_port") or 0) or None
    except (ValueError, TypeError):
        src_port = None
    try:
        dst_port = int(row.get("dst_port") or 0) or None
    except (ValueError, TypeError):
        dst_port = None

    node_id = (row.get("node_id") or "opencanary").strip()
    logdata = row.get("logdata") or {}
    if not isinstance(logdata, dict):
        logdata = {}

    ts = _parse_utc_time(row.get("utc_time") or row.get("local_time") or "")

    action    = _LOGTYPE_TO_ACTION[logtype]
    svc_name  = _LOGTYPE_TO_NAME.get(logtype, "Unknown")
    protocol  = _LOGTYPE_TO_PROTOCOL.get(logtype, "tcp")
    category  = _LOGTYPE_TO_CATEGORY.get(logtype, LogCategory.INTRUSION)

    username, password = _extract_credentials(logdata)

    msg = f"Honeypot {svc_name} bağlantı denemesi: {src_ip}"
    if username:
        msg += f" kullanıcı={username}"

    tags = ["honeypot", "opencanary", svc_name.lower()]
    if username:
        tags.append("credential_attempt")

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.OPENCANARY,
        observer_hostname=node_id,
        timestamp=ts,
        severity="critical",
        event_category=category,
        event_action=action,
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        network_protocol=protocol,
        username=username,
        message=msg,
        tags=tags,
        extra={
            "node_id":  node_id,
            "logtype":  logtype,
            "username": username,
            "password": password,
            "logdata":  logdata,
        },
    )
