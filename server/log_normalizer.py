"""
NetGuard — Log Normalizer

Farklı kaynaklardan (Suricata, Zeek, Wazuh, auth.log, syslog) gelen ham logları
ortak NormalizedLog formatına dönüştürür.

Pipeline:
  1. Ham log gelir (raw_content)
  2. Kaynak tipi tespit edilir (identify_source)
  3. Kaynağa uygun parser çağrılır
  4. NormalizedLog üretilir
  5. Log timestamp NTP validator ile doğrulanır — anormal ise tag eklenir
  6. Ham log + normalize log DB'ye yazılır
"""

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from server.database import db
from server.ntp_validator import ntp_validator
from server.parsers.firewall import detect_and_parse as _fw_detect_and_parse
from shared.models import (
    LogCategory,
    LogSourceType,
    NormalizedLog,
    RawLog,
)

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
#  Kaynak tespiti — regex ile hangi araçtan geldiğini anla
# ------------------------------------------------------------------ #

# Her kaynak için ayırt edici regex pattern
_SOURCE_PATTERNS: list[tuple[LogSourceType, re.Pattern]] = [
    # Suricata EVE JSON formatı
    (LogSourceType.SURICATA,  re.compile(r'"event_type"\s*:')),
    # Zeek TSV satırı — sekme ile ayrılmış, başında # veya zaman damgası
    (LogSourceType.ZEEK,      re.compile(r'^\d+\.\d+\t')),
    # Wazuh JSON — "rule" ve "agent" alanları içerir (çok satırlı JSON desteklenir)
    (LogSourceType.WAZUH,     re.compile(r'"rule"\s*:.*"agent"\s*:', re.DOTALL)),
    # Firewall logları — AUTH_LOG'dan önce kontrol edilmeli
    (LogSourceType.OPNSENSE,  re.compile(r'filterlog\[')),           # OPNsense (PID'li)
    (LogSourceType.PFSENSE,   re.compile(r'filterlog:')),            # pfSense (PID'siz)
    (LogSourceType.CISCO_ASA, re.compile(r'%ASA-')),
    (LogSourceType.FORTIGATE, re.compile(r'type=(?:traffic|utm)\b')),
    (LogSourceType.VYOS,      re.compile(r'kernel:.*SRC=[\d.]+.*DST=[\d.]+')),
    # auth.log — sshd veya sudo içerir
    (LogSourceType.AUTH_LOG,  re.compile(r'\b(sshd|sudo|su)\b')),
]


def identify_source(raw_content: str) -> LogSourceType:
    """Ham içeriği inceleyerek kaynak tipini döndür."""
    for source_type, pattern in _SOURCE_PATTERNS:
        if pattern.search(raw_content):
            return source_type
    return LogSourceType.SYSLOG


# ------------------------------------------------------------------ #
#  Parser'lar — her kaynak tipi için ayrı fonksiyon
# ------------------------------------------------------------------ #

# auth.log satırı örneği:
# Apr 12 10:23:45 myhost sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2
_AUTH_FAILED = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+'
    r'sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) '
    r'from (?P<src_ip>[\d.]+) port (?P<src_port>\d+)'
)

_AUTH_SUCCESS = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+'
    r'sshd\[\d+\]:\s+Accepted \S+ for (?P<user>\S+) '
    r'from (?P<src_ip>[\d.]+) port (?P<src_port>\d+)'
)

_AUTH_SUDO = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+'
    r'sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)'
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_auth_log_timestamp(month: str, day: str, time_str: str) -> datetime:
    """auth.log zaman damgasını UTC datetime'a çevir."""
    now = datetime.now(timezone.utc)
    month_num = _MONTHS.get(month, 1)
    h, m, s = map(int, time_str.split(":"))
    return datetime(now.year, month_num, int(day), h, m, s, tzinfo=timezone.utc)


def _parse_auth_log(raw: str, source_host: str) -> Optional[dict]:
    """auth.log satırını parse et."""
    m = _AUTH_FAILED.search(raw)
    if m:
        return dict(
            timestamp  = _parse_auth_log_timestamp(m["month"], m["day"], m["time"]),
            severity   = "warning",
            category   = LogCategory.AUTHENTICATION,
            event_type = "ssh_failure",
            src_ip     = m["src_ip"],
            src_port   = int(m["src_port"]),
            username   = m["user"],
            message    = f"SSH başarısız giriş: {m['user']}@{source_host} ({m['src_ip']})",
            tags       = ["ssh", "failed_login"],
        )

    m = _AUTH_SUCCESS.search(raw)
    if m:
        return dict(
            timestamp  = _parse_auth_log_timestamp(m["month"], m["day"], m["time"]),
            severity   = "info",
            category   = LogCategory.AUTHENTICATION,
            event_type = "ssh_success",
            src_ip     = m["src_ip"],
            src_port   = int(m["src_port"]),
            username   = m["user"],
            message    = f"SSH başarılı giriş: {m['user']}@{source_host} ({m['src_ip']})",
            tags       = ["ssh", "login_success"],
        )

    m = _AUTH_SUDO.search(raw)
    if m:
        return dict(
            timestamp  = _parse_auth_log_timestamp(m["month"], m["day"], m["time"]),
            severity   = "warning",
            category   = LogCategory.SYSTEM,
            event_type = "sudo_usage",
            username   = m["user"],
            message    = f"Sudo kullanımı: {m['user']} → {m['command'].strip()}",
            tags       = ["sudo", "privilege_escalation"],
        )

    return None


def _parse_suricata(raw: str, source_host: str) -> Optional[dict]:
    """Suricata EVE JSON formatını parse et."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None

    event_type = data.get("event_type", "unknown")
    timestamp_str = data.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        ts = datetime.now(timezone.utc)

    src_ip   = data.get("src_ip")
    dst_ip   = data.get("dest_ip")
    src_port = data.get("src_port")
    dst_port = data.get("dest_port")

    if event_type == "alert":
        rule = data.get("alert", {})
        return dict(
            timestamp  = ts,
            severity   = "critical" if rule.get("severity", 3) <= 1 else "warning",
            category   = LogCategory.INTRUSION,
            event_type = "suricata_alert",
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            src_port   = src_port,
            dst_port   = dst_port,
            message    = rule.get("signature", "Suricata alert"),
            tags       = ["suricata", "ids_alert", rule.get("category", "")],
        )

    if event_type == "dns":
        dns = data.get("dns", {})
        return dict(
            timestamp  = ts,
            severity   = "info",
            category   = LogCategory.NETWORK,
            event_type = "dns_query",
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            message    = f"DNS sorgusu: {dns.get('rrname', '')} ({dns.get('rrtype', '')})",
            tags       = ["suricata", "dns"],
        )

    # Diğer Suricata event tipleri (flow, http, tls vb.)
    return dict(
        timestamp  = ts,
        severity   = "info",
        category   = LogCategory.NETWORK,
        event_type = f"suricata_{event_type}",
        src_ip     = src_ip,
        dst_ip     = dst_ip,
        src_port   = src_port,
        dst_port   = dst_port,
        message    = f"Suricata {event_type} olayı",
        tags       = ["suricata", event_type],
    )


def _parse_zeek(raw: str, source_host: str) -> Optional[dict]:
    """Zeek TSV conn.log satırını parse et."""
    # Zeek conn.log sütunları: ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto ...
    parts = raw.strip().split("\t")
    if len(parts) < 6:
        return None

    try:
        ts = datetime.fromtimestamp(float(parts[0]), tz=timezone.utc)
    except (ValueError, IndexError):
        ts = datetime.now(timezone.utc)

    src_ip   = parts[2] if len(parts) > 2 else None
    src_port = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else None
    dst_ip   = parts[4] if len(parts) > 4 else None
    dst_port = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else None
    proto    = parts[6] if len(parts) > 6 else "unknown"

    return dict(
        timestamp  = ts,
        severity   = "info",
        category   = LogCategory.NETWORK,
        event_type = "zeek_connection",
        src_ip     = src_ip,
        dst_ip     = dst_ip,
        src_port   = src_port,
        dst_port   = dst_port,
        message    = f"Zeek bağlantı: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto})",
        tags       = ["zeek", "connection", proto],
    )


def _parse_wazuh(raw: str, source_host: str) -> Optional[dict]:
    """Wazuh JSON alert formatını parse et."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None

    rule     = data.get("rule", {})
    agent    = data.get("agent", {})
    full_log = data.get("full_log", "")

    timestamp_str = data.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        ts = datetime.now(timezone.utc)

    level = rule.get("level", 0)
    severity = "critical" if level >= 12 else ("warning" if level >= 7 else "info")

    return dict(
        timestamp  = ts,
        severity   = severity,
        category   = LogCategory.SYSTEM,
        event_type = f"wazuh_rule_{rule.get('id', 'unknown')}",
        src_ip     = data.get("srcip"),
        username   = data.get("srcuser"),
        message    = rule.get("description", full_log[:200]),
        tags       = ["wazuh"] + rule.get("groups", []),
    )


def _parse_syslog(raw: str, source_host: str) -> Optional[dict]:
    """Genel syslog satırını parse et — bilinen bir format bulunamazsa."""
    return dict(
        timestamp  = datetime.now(timezone.utc),
        severity   = "info",
        category   = LogCategory.SYSTEM,
        event_type = "syslog",
        message    = raw[:500],
        tags       = ["syslog"],
    )


def _parse_firewall(raw: str, source_host: str) -> Optional[dict]:
    """Firewall log satırını parsers.firewall modülüyle işle."""
    norm = _fw_detect_and_parse(raw)
    if norm is None:
        return None
    return {
        "timestamp": norm.timestamp,
        "severity":  norm.severity,
        "category":  norm.category,
        "event_type": norm.event_type,
        "src_ip":    norm.src_ip,
        "dst_ip":    norm.dst_ip,
        "src_port":  norm.src_port,
        "dst_port":  norm.dst_port,
        "protocol":  norm.protocol,
        "message":   norm.message,
        "tags":      list(norm.tags),
        "extra":     dict(norm.extra),
    }


_PARSERS = {
    LogSourceType.AUTH_LOG  : _parse_auth_log,
    LogSourceType.SURICATA  : _parse_suricata,
    LogSourceType.ZEEK      : _parse_zeek,
    LogSourceType.WAZUH     : _parse_wazuh,
    LogSourceType.SYSLOG    : _parse_syslog,
    LogSourceType.NETGUARD  : _parse_syslog,
    LogSourceType.PFSENSE   : _parse_firewall,
    LogSourceType.OPNSENSE  : _parse_firewall,
    LogSourceType.CISCO_ASA : _parse_firewall,
    LogSourceType.FORTIGATE : _parse_firewall,
    LogSourceType.VYOS      : _parse_firewall,
}


# ------------------------------------------------------------------ #
#  Ana normalize fonksiyonu
# ------------------------------------------------------------------ #

def normalize(raw_content: str, source_host: str) -> Optional[NormalizedLog]:
    """
    Ham log içeriğini alır, kaynağı tespit eder, parse eder,
    NormalizedLog döndürür.
    Başarısız olursa None döner.
    """
    source_type = identify_source(raw_content)
    parser = _PARSERS.get(source_type, _parse_syslog)
    parsed = parser(raw_content, source_host)

    if parsed is None:
        logger.debug(f"Parse başarısız: {source_host} / {source_type.value}")
        return None

    # Log timestamp doğrulaması
    ts = parsed.get("timestamp")
    tags: list = list(parsed.get("tags", []))
    if ts is not None:
        valid, reason = ntp_validator.validate_log_timestamp(ts)
        if not valid:
            tags.append(f"timestamp_anomaly:{reason}")
            logger.warning(f"Log timestamp anomalisi ({source_host}): {reason}")
    parsed["tags"] = tags

    return NormalizedLog(
        log_id      = str(uuid.uuid4()),
        raw_id      = "",           # Çağıran tarafından doldurulur
        source_type = source_type,
        source_host = source_host,
        **parsed,
    )


def process_and_store(raw_content: str, source_host: str) -> Optional[NormalizedLog]:
    """
    Ham logu al → normalize et → ikisini de DB'ye yaz.
    Dışarıdan çağrılacak ana fonksiyon budur.
    """
    raw_id = str(uuid.uuid4())
    source_type = identify_source(raw_content)

    # 1. Ham logu kaydet
    raw = RawLog(
        raw_id      = raw_id,
        source_type = source_type,
        source_host = source_host,
        raw_content = raw_content,
    )
    db.save_raw_log(raw)

    # 2. Normalize et
    norm = normalize(raw_content, source_host)
    if norm is None:
        return None

    norm.raw_id = raw_id

    # 3. Normalize logu kaydet
    db.save_normalized_log(norm)

    # 4. Ham logu normalize edildi olarak işaretle
    db.mark_raw_normalized(raw_id, norm.log_id)

    logger.info(f"Log normalize edildi: {source_host} / {source_type.value} / {norm.event_type}")
    return norm
