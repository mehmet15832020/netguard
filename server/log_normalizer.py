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
from datetime import datetime, timedelta, timezone
from typing import Optional

from server.database import db
from server.dhcp_baseline import check_dhcp_mac_baseline
from server.dns_resolver import resolve_and_update_bg
from server.log_store import log_store
from server.ntp_validator import ntp_validator
from server.parsers.firewall import detect_and_parse as _fw_detect_and_parse
from server.parsers.suricata import parse_eve_line as _suricata_parse_eve_line
from server.parsers.web_log import detect_and_parse as _web_detect_and_parse
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
    (LogSourceType.SURICATA,  re.compile(r'"event_action"\s*:')),
    # Zeek TSV satırı — sekme ile ayrılmış, başında # veya zaman damgası
    (LogSourceType.ZEEK,      re.compile(r'^\d+\.\d+\t')),
    # Wazuh JSON — "rule" ve "agent" alanları içerir (çok satırlı JSON desteklenir)
    (LogSourceType.WAZUH,     re.compile(r'"rule"\s*:.*"agent"\s*:', re.DOTALL)),
    # DHCP syslog — F1, marka bağımsız (ISC dhcpd/Kea/FortiGate). FORTIGATE
    # pattern'inden ÖNCE kontrol edilmeli: FortiGate DHCP olayları type=event
    # kullanır (FORTIGATE pattern'iyle çakışmaz) ama tutarlılık için burada.
    (LogSourceType.DHCP,      re.compile(
        r'dhcpd(?:\[\d+\])?:\s+DHCP(?:ACK|NAK|DECLINE)\b'
        r'|DHCP4_LEASE_(?:ALLOC|RENEW)\b'
        r'|subtype="?dhcp"?\b',
    )),
    # DNS resolver syslog — F2, marka bağımsız (Unbound/dnsmasq/FortiGate DNS filter).
    # FORTIGATE pattern'inden ÖNCE ZORUNLU: FortiGate DNS filter logu
    # type=utm subtype=dns kullanır — FORTIGATE pattern'i (type=utm) de eşleşir,
    # subtype kontrolü olmadan yanlış kaynağa (FORTIGATE) düşer.
    (LogSourceType.DNS_RESOLVER, re.compile(
        r'\bunbound\b.*\binfo:\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+\s+[A-Z]+\s+IN\b'
        r'|\bdnsmasq\b.*\bquery\[[A-Z]+\]'
        r'|subtype="?dns"?\b',
    )),
    # Firewall yönetim erişimi (F3) — admin login/auth olayları, CIS Control 8.11.
    # FortiGate/pfSense pattern'lerinin yanında, AUTH_LOG'dan ÖNCE.
    (LogSourceType.FORTIGATE, re.compile(r'subtype="?system"?\b.*\baction="?login"?\b')),
    (LogSourceType.OPNSENSE,  re.compile(r'php-fpm(?:\[\d+\])?:\s+/index\.php:\s+(?:Successful login|webConfigurator authentication error)')),
    # Firewall logları — AUTH_LOG'dan önce kontrol edilmeli
    (LogSourceType.OPNSENSE,  re.compile(r'filterlog\[')),           # OPNsense (PID'li)
    (LogSourceType.PFSENSE,   re.compile(r'filterlog:')),            # pfSense (PID'siz)
    (LogSourceType.CISCO_ASA, re.compile(r'%ASA-')),
    # G1 — Cisco IOS/NX-OS router BGP + interface events (%BGP- / %LINK- / %LINEPROTO-)
    (LogSourceType.CISCO_IOS, re.compile(r'%(?:BGP|LINK|LINEPROTO)-\d+-\w+')),
    # G1 — Juniper Junos RPD BGP + SNMP link trap
    (LogSourceType.JUNIPER,   re.compile(r'RPD_BGP_NEIGHBOR_STATE_CHANGED|SNMP_TRAP_LINK_(?:DOWN|UP)')),
    # G1 — MikroTik RouterOS interface syslog
    (LogSourceType.MIKROTIK,  re.compile(r'interface,(?:info|error|warning)\s+\S+\s+link\s+(?:up|down)')),
    (LogSourceType.FORTIGATE, re.compile(r'type="?(?:traffic|utm)"?\b')),
    (LogSourceType.VYOS,      re.compile(
        r'kernel:.*SRC=[\d.]+.*DST=[\d.]+'
        # F3 — VyOS SSH bağlam kaybı düzeltmesi: router/vyos hostname'li sshd
        # satırları AUTH_LOG'a değil VYOS'a düşmeli (yönetim erişimi bağlamı).
        r'|\w+\s+\d+\s+[\d:]+\s+(?:vyos|router|gw|edge)\S*\s+sshd\b',
    )),
    # nginx access/error log — "nginx:" process tag + combined log format IP
    (LogSourceType.NGINX,     re.compile(r'\bnginx\b.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')),
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
    r'from (?P<source_ip>[\d.]+) port (?P<source_port>\d+)'
)

_AUTH_SUCCESS = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+'
    r'sshd\[\d+\]:\s+Accepted \S+ for (?P<user>\S+) '
    r'from (?P<source_ip>[\d.]+) port (?P<source_port>\d+)'
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
    dt = datetime(now.year, month_num, int(day), h, m, s, tzinfo=timezone.utc)
    if dt > now + timedelta(days=1):
        dt = dt.replace(year=now.year - 1)
    return dt


def _parse_auth_log(raw: str, observer_hostname: str) -> Optional[dict]:
    """auth.log satırını parse et."""
    m = _AUTH_FAILED.search(raw)
    if m:
        return dict(
            timestamp  = _parse_auth_log_timestamp(m["month"], m["day"], m["time"]),
            severity   = "warning",
            event_category   = LogCategory.AUTHENTICATION,
            event_action = "ssh_failure",
            source_ip     = m["source_ip"],
            source_port   = int(m["source_port"]),
            destination_ip     = observer_hostname,
            destination_port   = 22,
            network_protocol   = "tcp",
            username   = m["user"],
            message    = f"SSH başarısız giriş: {m['user']}@{observer_hostname} ({m['source_ip']})",
            tags       = ["ssh", "failed_login"],
        )

    m = _AUTH_SUCCESS.search(raw)
    if m:
        return dict(
            timestamp  = _parse_auth_log_timestamp(m["month"], m["day"], m["time"]),
            severity   = "info",
            event_category   = LogCategory.AUTHENTICATION,
            event_action = "ssh_success",
            source_ip     = m["source_ip"],
            source_port   = int(m["source_port"]),
            destination_ip     = observer_hostname,
            destination_port   = 22,
            network_protocol   = "tcp",
            username   = m["user"],
            message    = f"SSH başarılı giriş: {m['user']}@{observer_hostname} ({m['source_ip']})",
            tags       = ["ssh", "login_success"],
        )

    m = _AUTH_SUDO.search(raw)
    if m:
        return dict(
            timestamp  = _parse_auth_log_timestamp(m["month"], m["day"], m["time"]),
            severity   = "warning",
            event_category   = LogCategory.SYSTEM,
            event_action = "sudo_usage",
            username   = m["user"],
            message    = f"Sudo kullanımı: {m['user']} → {m['command'].strip()}",
            tags       = ["sudo", "privilege_escalation"],
        )

    return None


def _parse_suricata(raw: str, observer_hostname: str) -> Optional[dict]:
    """Suricata EVE JSON satırını parsers.suricata modülüne delege et."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    norm = _suricata_parse_eve_line(data)
    if norm is None:
        return None
    return {
        "timestamp":        norm.timestamp,
        "severity":         norm.severity,
        "event_category":   norm.event_category,
        "event_action":     norm.event_action,
        "source_ip":        norm.source_ip,
        "destination_ip":   norm.destination_ip,
        "source_port":      norm.source_port,
        "destination_port": norm.destination_port,
        "network_protocol": norm.network_protocol,
        "message":          norm.message,
        "tags":             list(norm.tags),
        "extra":            dict(norm.extra),
    }


def _parse_zeek(raw: str, observer_hostname: str) -> Optional[dict]:
    """Zeek TSV conn.log satırını parse et."""
    # Zeek conn.log sütunları: ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto ...
    parts = raw.strip().split("\t")
    if len(parts) < 6:
        return None

    try:
        ts = datetime.fromtimestamp(float(parts[0]), tz=timezone.utc)
    except (ValueError, IndexError):
        ts = datetime.now(timezone.utc)

    source_ip   = parts[2] if len(parts) > 2 else None
    source_port = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else None
    destination_ip   = parts[4] if len(parts) > 4 else None
    destination_port = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else None
    proto    = parts[6] if len(parts) > 6 else "unknown"

    return dict(
        timestamp  = ts,
        severity   = "info",
        event_category   = LogCategory.NETWORK,
        event_action = "zeek_connection",
        source_ip     = source_ip,
        destination_ip     = destination_ip,
        source_port   = source_port,
        destination_port   = destination_port,
        message    = f"Zeek bağlantı: {source_ip}:{source_port} → {destination_ip}:{destination_port} ({proto})",
        tags       = ["zeek", "connection", proto],
    )


def _parse_wazuh(raw: str, observer_hostname: str) -> Optional[dict]:
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
        event_category   = LogCategory.SYSTEM,
        event_action = f"wazuh_rule_{rule.get('id', 'unknown')}",
        source_ip     = data.get("srcip"),
        username   = data.get("srcuser"),
        message    = rule.get("description", full_log[:200]),
        tags       = ["wazuh"] + rule.get("groups", []),
    )


def _parse_syslog(raw: str, observer_hostname: str) -> Optional[dict]:
    """Genel syslog satırını parse et — bilinen bir format bulunamazsa."""
    return dict(
        timestamp      = datetime.now(timezone.utc),
        severity       = "info",
        event_category = LogCategory.SYSTEM,
        event_action   = "syslog",
        source_ip      = None,
        message        = raw[:500],
        tags           = ["syslog"],
    )


# nginx combined log: "IP - user [timestamp] ..." — syslog header öncesinde olabilir
_COMBINED_IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}\s+-\s+\S+\s+\[)')
_NGINX_ERROR_START_RE = re.compile(r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})')


def _parse_web_log(raw: str, observer_hostname: str) -> Optional[dict]:
    """nginx access/error log satırını parse et — syslog başlığını soyarak."""
    m = _COMBINED_IP_RE.search(raw)
    if m:
        line = raw[m.start():]
    else:
        m2 = _NGINX_ERROR_START_RE.search(raw)
        line = raw[m2.start():] if m2 else raw

    norm = _web_detect_and_parse(line, observer_hostname)
    if norm is None:
        return None
    return {
        "timestamp":  norm.timestamp,
        "severity":   norm.severity,
        "event_category":   norm.event_category,
        "event_action": norm.event_action,
        "source_ip":     norm.source_ip,
        "destination_ip":     norm.destination_ip,
        "source_port":   norm.source_port,
        "destination_port":   norm.destination_port,
        "network_protocol":   norm.network_protocol,
        "message":    norm.message,
        "tags":       list(norm.tags),
        "extra":      dict(norm.extra),
    }


def _parse_firewall(raw: str, observer_hostname: str) -> Optional[dict]:
    """Firewall log satırını parsers.firewall modülüyle işle."""
    norm = _fw_detect_and_parse(raw)
    if norm is None:
        return None
    return {
        "timestamp": norm.timestamp,
        "severity":  norm.severity,
        "event_category":  norm.event_category,
        "event_action": norm.event_action,
        "source_ip":    norm.source_ip,
        "destination_ip":    norm.destination_ip,
        "source_port":  norm.source_port,
        "destination_port":  norm.destination_port,
        "network_protocol":  norm.network_protocol,
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
    LogSourceType.VYOS       : _parse_firewall,
    LogSourceType.DHCP       : _parse_firewall,
    LogSourceType.DNS_RESOLVER : _parse_firewall,
    LogSourceType.CISCO_IOS  : _parse_firewall,
    LogSourceType.JUNIPER    : _parse_firewall,
    LogSourceType.MIKROTIK   : _parse_firewall,
    LogSourceType.NGINX      : _parse_web_log,
}


# ------------------------------------------------------------------ #
#  Ana normalize fonksiyonu
# ------------------------------------------------------------------ #

def normalize(raw_content: str, observer_hostname: str) -> Optional[NormalizedLog]:
    """
    Ham log içeriğini alır, kaynağı tespit eder, parse eder,
    NormalizedLog döndürür.
    Başarısız olursa None döner.
    """
    source_type = identify_source(raw_content)
    parser = _PARSERS.get(source_type, _parse_syslog)
    parsed = parser(raw_content, observer_hostname)

    if parsed is None:
        logger.debug(f"Parse başarısız: {observer_hostname} / {source_type.value}")
        return None

    # Log timestamp doğrulaması
    ts = parsed.get("timestamp")
    tags: list = list(parsed.get("tags", []))
    if ts is not None:
        valid, reason = ntp_validator.validate_log_timestamp(ts)
        if not valid:
            tags.append(f"timestamp_anomaly:{reason}")
            logger.warning(f"Log timestamp anomalisi ({observer_hostname}): {reason}")
    parsed["tags"] = tags

    parsed_hostname = parsed.pop("observer_hostname", observer_hostname)
    return NormalizedLog(
        log_id            = str(uuid.uuid4()),
        raw_id            = "",
        source_type       = source_type,
        observer_hostname = parsed_hostname,
        **parsed,
    )


def process_and_store(raw_content: str, observer_hostname: str) -> Optional[NormalizedLog]:
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
        observer_hostname = observer_hostname,
        raw_content = raw_content,
    )
    db.save_raw_log(raw)

    # 2. Normalize et
    norm = normalize(raw_content, observer_hostname)
    if norm is None:
        db.mark_raw_parse_failed(raw_id)
        return None

    norm.raw_id = raw_id

    # 3. Normalize logu kaydet (hostname'ler henüz boş — arka planda doldurulacak)
    log_store.save(norm)

    # 3b. Firewall DHCP lease kaydı — Zeek dhcp.log (C1) ile aynı MAC baseline'ı
    # paylaşır (F1, server/dhcp_baseline.py)
    if norm.event_action == "dhcp_lease":
        try:
            extra_log = check_dhcp_mac_baseline(norm)
            if extra_log is not None:
                log_store.save(extra_log)
        except Exception as exc:
            logger.error(f"DHCP MAC baseline hatası: {exc}")

    # 4. DNS arka planda çöz ve DB'yi güncelle (event loop'u bloklamaz)
    resolve_and_update_bg(norm.log_id, norm.source_ip, norm.destination_ip)

    # 5. Ham logu normalize edildi olarak işaretle
    db.mark_raw_normalized(raw_id, norm.log_id)

    logger.info(f"Log normalize edildi: {observer_hostname} / {source_type.value} / {norm.event_action}")
    return norm
