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
    observer_hostname: str,
    event_action: str,
    severity: str,
    event_category: LogCategory,
    message: str,
    raw_content: str,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    destination_port: Optional[int] = None,
    network_protocol: Optional[str] = None,
    tags: Optional[list] = None,
    extra: Optional[dict] = None,
) -> NormalizedLog:
    now = datetime.now(timezone.utc)
    return NormalizedLog(
        log_id      = str(uuid.uuid4()),
        raw_id      = str(uuid.uuid4()),
        source_type = source_type,
        observer_hostname = observer_hostname,
        timestamp   = now,
        severity    = severity,
        event_category    = event_category,
        event_action  = event_action,
        source_ip      = source_ip,
        destination_ip      = destination_ip,
        source_port    = source_port,
        destination_port    = destination_port,
        network_protocol    = network_protocol,
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
    observer_hostname = hm.group(1) if hm else "pfsense"

    try:
        action    = parts[6].lower()
        direction = parts[7].lower()
        network_protocol  = parts[16].lower()
        source_ip    = parts[18]
        destination_ip    = parts[19] if len(parts) > 19 else None
        source_port  = int(parts[20]) if len(parts) > 20 and parts[20].isdigit() else None
        destination_port  = int(parts[21]) if len(parts) > 21 and parts[21].isdigit() else None
    except (IndexError, ValueError):
        return None

    blocked   = action == "block"
    severity  = "warning" if blocked else "info"
    event_action = "fw_block" if blocked else "fw_allow"
    msg = (
        f"pfSense {action.upper()} {direction.upper()} "
        f"{network_protocol.upper()} {source_ip}:{source_port} → {destination_ip}:{destination_port}"
    )

    return _make_log(
        source_type = LogSourceType.PFSENSE,
        observer_hostname = observer_hostname,
        event_action  = event_action,
        severity    = severity,
        event_category    = LogCategory.NETWORK,
        message     = msg,
        raw_content = line,
        source_ip      = source_ip,
        destination_ip      = destination_ip,
        source_port    = source_port,
        destination_port    = destination_port,
        network_protocol    = network_protocol,
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
    observer_hostname = hm.group(1) if hm else "cisco-asa"

    source_ip = destination_ip = None
    source_port = destination_port = None
    blocked = False

    dm = _ASA_DENY_RE.search(msg_raw)
    if dm:
        source_ip, source_port = dm.group("src"), int(dm.group("sport"))
        destination_ip, destination_port = dm.group("dst"), int(dm.group("dport"))
        blocked  = True
        severity = severity if severity in ("critical", "high") else "warning"
    else:
        pm = _ASA_PERMIT_RE.search(msg_raw)
        if pm:
            source_ip, source_port = pm.group("src"), int(pm.group("sport"))
            destination_ip, destination_port = pm.group("dst"), int(pm.group("dport"))

    return _make_log(
        source_type = LogSourceType.CISCO_ASA,
        observer_hostname = observer_hostname,
        event_action  = "fw_block" if blocked else "fw_allow",
        severity    = severity,
        event_category    = LogCategory.NETWORK,
        message     = f"ASA-{level}-{code}: {msg_raw}",
        raw_content = line,
        source_ip      = source_ip,
        destination_ip      = destination_ip,
        source_port    = source_port,
        destination_port    = destination_port,
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
    source_ip   = kv.get("srcip")
    destination_ip   = kv.get("dstip")
    source_port = int(kv["srcport"]) if kv.get("srcport", "").isdigit() else None
    destination_port = int(kv["dstport"]) if kv.get("dstport", "").isdigit() else None
    proto_n  = kv.get("proto", "")
    proto    = {"6": "tcp", "17": "udp", "1": "icmp"}.get(proto_n, proto_n or "")
    severity = _FORTI_LEVEL_MAP.get(kv.get("level", "").lower(), "info")
    blocked  = action in ("deny", "drop", "block", "reset")
    if blocked and severity == "info":
        severity = "warning"

    msg = (
        f"FortiGate {action.upper()} "
        f"{proto.upper() or 'PKT'} "
        f"{source_ip}:{source_port} → {destination_ip}:{destination_port}"
    )

    return _make_log(
        source_type = LogSourceType.FORTIGATE,
        observer_hostname = kv.get("devname", "fortigate"),
        event_action  = "fw_block" if blocked else "fw_allow",
        severity    = severity,
        event_category    = LogCategory.NETWORK,
        message     = msg,
        raw_content = line,
        source_ip      = source_ip,
        destination_ip      = destination_ip,
        source_port    = source_port,
        destination_port    = destination_port,
        network_protocol    = proto or None,
        tags        = [action, proto, f"policy:{kv.get('policyid','?')}"],
        extra       = {"action": action, "policy": kv.get("policyid"), "devname": kv.get("devname")},
    )


# ──────────────────────────────────────────────────────────────────
#  OPNsense parser
#  OPNsense filterlog satırı pfSense'ten farklı olarak PID içerir:
#  <134>Apr 26 10:00:01 OPNsense filterlog[12345]: 82,,,0,vtnet1,match,block,...
# ──────────────────────────────────────────────────────────────────

_OPNSENSE_HOST_RE   = re.compile(r'(?:<\d+>)?\w+\s+\d+\s+[\d:]+\s+(\S+)\s+filterlog\[')
_OPNSENSE_FIELDS_RE = re.compile(r'filterlog\[\d+\]:\s+(.+)$')


def parse_opnsense(line: str) -> Optional[NormalizedLog]:
    fm = _OPNSENSE_FIELDS_RE.search(line)
    if not fm:
        return None
    parts = fm.group(1).split(",")
    if len(parts) < 19:
        return None

    hm = _OPNSENSE_HOST_RE.search(line)
    observer_hostname = hm.group(1) if hm else "opnsense"

    try:
        action    = parts[6].lower()
        direction = parts[7].lower()
        network_protocol  = parts[16].lower()
        source_ip    = parts[18]
        destination_ip    = parts[19] if len(parts) > 19 else None
        source_port  = int(parts[20]) if len(parts) > 20 and parts[20].isdigit() else None
        destination_port  = int(parts[21]) if len(parts) > 21 and parts[21].isdigit() else None
    except (IndexError, ValueError):
        return None

    blocked    = action == "block"
    severity   = "warning" if blocked else "info"
    event_action = "fw_block" if blocked else "fw_allow"
    msg = (
        f"OPNsense {action.upper()} {direction.upper()} "
        f"{network_protocol.upper()} {source_ip}:{source_port} → {destination_ip}:{destination_port}"
    )

    return _make_log(
        source_type = LogSourceType.OPNSENSE,
        observer_hostname = observer_hostname,
        event_action  = event_action,
        severity    = severity,
        event_category    = LogCategory.NETWORK,
        message     = msg,
        raw_content = line,
        source_ip      = source_ip,
        destination_ip      = destination_ip,
        source_port    = source_port,
        destination_port    = destination_port,
        network_protocol    = network_protocol,
        tags        = [action, direction],
        extra       = {"action": action, "direction": direction, "interface": parts[4]},
    )


# ──────────────────────────────────────────────────────────────────
#  VyOS / iptables kernel log parser
#  Apr 26 10:00:01 vyos kernel: [VyOS-FW-DROP] IN=eth0 OUT= SRC=10.0.30.1
#  DST=192.168.1.1 PROTO=TCP SPT=12345 DPT=443 ...
# ──────────────────────────────────────────────────────────────────

_VYOS_HOST_RE   = re.compile(r'\w+\s+\d+\s+[\d:]+\s+(\S+)\s+kernel:')
_VYOS_ACTION_RE = re.compile(r'\[([A-Za-z_-]+)\]')
_VYOS_FIELDS_RE = re.compile(
    r'SRC=(?P<src>[\d.]+).*?DST=(?P<dst>[\d.]+).*?PROTO=(?P<proto>\w+)'
    r'(?:.*?SPT=(?P<sport>\d+))?(?:.*?DPT=(?P<dport>\d+))?',
    re.DOTALL,
)


def parse_vyos(line: str) -> Optional[NormalizedLog]:
    if "SRC=" not in line or "DST=" not in line:
        return None

    hm = _VYOS_HOST_RE.search(line)
    observer_hostname = hm.group(1) if hm else "vyos"

    am = _VYOS_ACTION_RE.search(line)
    action_tag = am.group(1) if am else ""
    blocked = any(w in action_tag.upper() for w in ("DROP", "BLOCK", "REJECT", "DENY"))

    fm = _VYOS_FIELDS_RE.search(line)
    if not fm:
        return None

    source_ip   = fm.group("src")
    destination_ip   = fm.group("dst")
    network_protocol = fm.group("proto").lower()
    source_port = int(fm.group("sport")) if fm.group("sport") else None
    destination_port = int(fm.group("dport")) if fm.group("dport") else None

    action     = "block" if blocked else "allow"
    severity   = "warning" if blocked else "info"
    event_action = "fw_block" if blocked else "fw_allow"
    msg = (
        f"VyOS {action.upper()} "
        f"{network_protocol.upper()} {source_ip}:{source_port} → {destination_ip}:{destination_port}"
    )

    return _make_log(
        source_type = LogSourceType.VYOS,
        observer_hostname = observer_hostname,
        event_action  = event_action,
        severity    = severity,
        event_category    = LogCategory.NETWORK,
        message     = msg,
        raw_content = line,
        source_ip      = source_ip,
        destination_ip      = destination_ip,
        source_port    = source_port,
        destination_port    = destination_port,
        network_protocol    = network_protocol,
        tags        = [action, action_tag.lower()],
        extra       = {"action": action, "action_tag": action_tag, "interface": ""},
    )


# ──────────────────────────────────────────────────────────────────
#  DHCP syslog parser'ları (F1) — marka bağımsız
#  Firewall'lar LAN'ın yetkili DHCP sunucusudur; bu loglar IP→MAC→hostname
#  eşlemesi sağlar (NIST SP 800-94 §3.3, CIS Controls v8 Control 12.2).
#  Zeek dhcp.log (C1, pasif gözlem) ile tamamlayıcıdır — server/dhcp_baseline.py
#  aynı dhcp_mac_history tablosunu paylaşır.
#
#  Sadece lease SONUCU taşıyan mesaj tipleri işlenir (ACK/NAK/DECLINE) —
#  DISCOVER/OFFER/REQUEST/RELEASE protokol adımları, tek başına IP→MAC
#  bilgisi taşımaz, gürültü.
# ──────────────────────────────────────────────────────────────────

_DHCPD_HOST_RE = re.compile(r'\w+\s+\d+\s+[\d:]+\s+(\S+)\s+dhcpd')
_DHCPD_LINE_RE = re.compile(r'dhcpd(?:\[\d+\])?:\s+(DHCPACK|DHCPNAK|DHCPDECLINE)\s+(.*)$')
_DHCP_IP_RE    = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_DHCP_MAC_RE   = re.compile(r'\b([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})\b')
_DHCP_VIA_RE   = re.compile(r'\bvia\s+(\S+)')
_DHCP_PAREN_RE = re.compile(r'\(([^)]+)\)')


def parse_isc_dhcpd(line: str) -> Optional[NormalizedLog]:
    """
    ISC dhcpd — OPNsense/pfSense/VyOS hepsi bu daemon'u kullanır (kb.isc.org doğrulandı).
    Örnek: "dhcpd: DHCPACK on 192.168.1.10 to aa:bb:cc:dd:ee:ff (hostname) via eth0"
    """
    lm = _DHCPD_LINE_RE.search(line)
    if not lm:
        return None
    msg_type, rest = lm.group(1), lm.group(2)

    mac_m = _DHCP_MAC_RE.search(rest)
    if not mac_m:
        return None
    mac = mac_m.group(1)

    ip_matches = _DHCP_IP_RE.findall(rest)
    assigned_ip = ip_matches[0] if ip_matches else None
    if not assigned_ip:
        return None

    hostname = ""
    for paren in _DHCP_PAREN_RE.findall(rest):
        if not _DHCP_IP_RE.fullmatch(paren):
            hostname = paren
            break

    iface_m = _DHCP_VIA_RE.search(rest)
    interface = iface_m.group(1) if iface_m else ""

    hm = _DHCPD_HOST_RE.search(line)
    observer_hostname = hm.group(1) if hm else "dhcp-server"

    severity = "warning" if msg_type in ("DHCPNAK", "DHCPDECLINE") else "info"
    msg = f"DHCP {msg_type}: {assigned_ip} ↔ {mac}"
    if hostname:
        msg += f" ({hostname})"

    return _make_log(
        source_type = LogSourceType.DHCP,
        observer_hostname = observer_hostname,
        event_action  = "dhcp_lease",
        severity    = severity,
        event_category    = LogCategory.NETWORK,
        message     = msg,
        raw_content = line,
        source_ip      = assigned_ip,
        tags        = ["dhcp", "isc-dhcpd", msg_type.lower()],
        extra       = {
            "mac": mac, "hostname": hostname, "msg_type": msg_type,
            "interface": interface, "vendor": "isc-dhcpd",
        },
    )


# Kea DHCP4 — düz metin log formatı (JSON DEĞİL — orijinal varsayım hatalıydı,
# kb.isc.org/docs/isc-dhcp-logging-compared-to-kea ile doğrulandı).
# Örnek: "DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:ff], cid=..., tid=...: lease 192.168.1.10 has been allocated"
_KEA_DHCP_RE = re.compile(
    r'(DHCP4_LEASE_ALLOC|DHCP4_LEASE_RENEW)\s+\[hwtype=\d+\s+'
    r'(?P<mac>[0-9a-fA-F:]{17})\].*?lease\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'\s+has been (?:allocated|renewed)',
    re.IGNORECASE,
)


def parse_kea_dhcp(line: str) -> Optional[NormalizedLog]:
    """Kea DHCP4 (yeni OPNsense sürümleri) — sadece ALLOC/RENEW (lease sonucu)."""
    m = _KEA_DHCP_RE.search(line)
    if not m:
        return None

    mac = m.group("mac")
    ip  = m.group("ip")
    is_renew = m.group(1) == "DHCP4_LEASE_RENEW"

    msg = f"DHCP {'RENEW' if is_renew else 'ALLOC'}: {ip} ↔ {mac}"

    return _make_log(
        source_type = LogSourceType.DHCP,
        observer_hostname = "kea-dhcp4",
        event_action  = "dhcp_lease",
        severity    = "info",
        event_category    = LogCategory.NETWORK,
        message     = msg,
        raw_content = line,
        source_ip      = ip,
        tags        = ["dhcp", "kea", "renew" if is_renew else "alloc"],
        extra       = {"mac": mac, "hostname": "", "vendor": "kea-dhcp4"},
    )


def parse_fortigate_dhcp(line: str) -> Optional[NormalizedLog]:
    """
    FortiGate DHCP sunucu olayı — key=value format (parse_fortigate ile aynı
    _FORTI_KV_RE kullanılır). Not: mac/ip/hostname alan adları Fortinet'in
    resmi dokümantasyonunda DHCP-özel örnekle doğrulanamadı (genel KV format
    doğrulandı) — üretimde gerçek cihaz logu ile çapraz kontrol edilmeli.
    """
    if "subtype=" not in line or "dhcp" not in line.lower():
        return None
    kv = {k: v.strip('"') for k, v in _FORTI_KV_RE.findall(line)}
    if kv.get("subtype", "").lower() != "dhcp":
        return None

    mac = kv.get("mac")
    ip  = kv.get("ip") or kv.get("assigned_ip") or kv.get("srcip")
    if not mac or not ip:
        return None

    hostname = kv.get("hostname", "")
    action   = kv.get("action", "").lower()
    severity = "warning" if action in ("decline", "expire", "nak") else "info"

    msg = f"DHCP FortiGate {action or 'lease'}: {ip} ↔ {mac}"
    if hostname:
        msg += f" ({hostname})"

    return _make_log(
        source_type = LogSourceType.DHCP,
        observer_hostname = kv.get("devname", "fortigate"),
        event_action  = "dhcp_lease",
        severity    = severity,
        event_category    = LogCategory.NETWORK,
        message     = msg,
        raw_content = line,
        source_ip      = ip,
        tags        = ["dhcp", "fortigate", action] if action else ["dhcp", "fortigate"],
        extra       = {"mac": mac, "hostname": hostname, "vendor": "fortigate", "action": action},
    )


def parse_dhcp_syslog(line: str) -> Optional[NormalizedLog]:
    """Marka bağımsız DHCP syslog dispatcher (F1)."""
    if "dhcpd" in line and _DHCPD_LINE_RE.search(line):
        return parse_isc_dhcpd(line)
    if "DHCP4_LEASE_ALLOC" in line or "DHCP4_LEASE_RENEW" in line:
        return parse_kea_dhcp(line)
    if "subtype=" in line and "dhcp" in line.lower():
        return parse_fortigate_dhcp(line)
    return None


# ──────────────────────────────────────────────────────────────────
#  DNS resolver syslog parser'ları (F2) — marka bağımsız
#  Firewall'lar LAN istemcilerinin DNS resolver'ıdır; "hangi iç makine hangi
#  domaini sorguladı" bilgisi C2/DGA/tünelleme tespitine açar (MITRE T1071.004).
#  event_action="dns_query" — Zeek parse_dns() ile AYNI (server/parsers/zeek.py)
#  → mevcut DNS korelasyon/Sigma kuralları firewall kaynaklı sorguları da kapsar.
#
#  Not: Cisco ASA bilinçli olarak ÇIKARILDI — araştırmada orijinal görevdeki
#  örnek (%ASA-6-602303) gerçek değildi; gerçek ASA DNS mesajları (410001-410004)
#  inceleme/anomali bildirimleri, istemci→domain sorgu kaydı değil (ASA tipik
#  olarak LAN resolver'ı olarak kullanılmaz).
# ──────────────────────────────────────────────────────────────────

# Unbound (OPNsense/pfSense) — nlnetlabs.nl doğrulandı:
# "[1553775590] unbound[32655:0] info: 127.0.0.1 googlemail.l.google.com. A IN"
_UNBOUND_RE = re.compile(
    r'unbound(?:\[\d+(?::\d+)?\])?:?\s*(?:\[\d+:\d+\]\s+)?info:\s+'
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<domain>\S+?)\.?\s+'
    r'(?P<qtype>[A-Z]+)\s+IN\b'
)


def parse_unbound_dns(line: str) -> Optional[NormalizedLog]:
    m = _UNBOUND_RE.search(line)
    if not m:
        return None
    ip, domain, qtype = m.group("ip"), m.group("domain"), m.group("qtype")

    return _make_log(
        source_type = LogSourceType.DNS_RESOLVER,
        observer_hostname = "unbound",
        event_action  = "dns_query",
        severity    = "info",
        event_category    = LogCategory.NETWORK,
        message     = f"DNS {ip} → {domain} ({qtype})",
        raw_content = line,
        source_ip      = ip,
        tags        = ["dns", "unbound"],
        extra       = {"query_domain": domain, "query_type": qtype, "response_ip": "", "action": ""},
    )


# dnsmasq (küçük router'lar, Pi-hole) — man page formatı, yıllardır stabil:
# "dnsmasq[1234]: query[A] evil.com from 192.168.1.10"
_DNSMASQ_RE = re.compile(
    r'dnsmasq(?:\[\d+\])?:\s+query\[(?P<qtype>[A-Z]+)\]\s+(?P<domain>\S+)\s+from\s+'
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
)


def parse_dnsmasq_dns(line: str) -> Optional[NormalizedLog]:
    m = _DNSMASQ_RE.search(line)
    if not m:
        return None
    qtype, domain, ip = m.group("qtype"), m.group("domain"), m.group("ip")

    return _make_log(
        source_type = LogSourceType.DNS_RESOLVER,
        observer_hostname = "dnsmasq",
        event_action  = "dns_query",
        severity    = "info",
        event_category    = LogCategory.NETWORK,
        message     = f"DNS {ip} → {domain} ({qtype})",
        raw_content = line,
        source_ip      = ip,
        tags        = ["dns", "dnsmasq"],
        extra       = {"query_domain": domain, "query_type": qtype, "response_ip": "", "action": ""},
    )


def parse_fortigate_dns(line: str) -> Optional[NormalizedLog]:
    """
    FortiGate DNS filter — Fortinet dokümantasyonu tam doğrulandı:
    type="utm" subtype="dns" qname=... srcip=... ipaddr=<resolved> action=...
    """
    if "subtype=" not in line or "dns" not in line.lower():
        return None
    kv = {k: v.strip('"') for k, v in _FORTI_KV_RE.findall(line)}
    if kv.get("subtype", "").lower() != "dns":
        return None

    domain = kv.get("qname")
    src_ip = kv.get("srcip")
    if not domain or not src_ip:
        return None

    response_ip = kv.get("ipaddr", "")
    qtype       = kv.get("qtype", "")
    action      = kv.get("action", "").lower()
    blocked     = action in ("block", "redirect")
    severity    = "warning" if blocked else "info"

    msg = f"DNS {src_ip} → {domain} ({qtype}) [{action or 'pass'}]"

    return _make_log(
        source_type = LogSourceType.DNS_RESOLVER,
        observer_hostname = kv.get("devname", "fortigate"),
        event_action  = "dns_query",
        severity    = severity,
        event_category    = LogCategory.NETWORK,
        message     = msg,
        raw_content = line,
        source_ip      = src_ip,
        destination_ip      = response_ip or None,
        tags        = ["dns", "fortigate", action] if action else ["dns", "fortigate"],
        extra       = {
            "query_domain": domain, "query_type": qtype,
            "response_ip": response_ip, "action": action,
            "category": kv.get("catdesc", ""),
        },
    )


def parse_dns_resolver_syslog(line: str) -> Optional[NormalizedLog]:
    """Marka bağımsız DNS resolver syslog dispatcher (F2)."""
    if "unbound" in line:
        result = parse_unbound_dns(line)
        if result is not None:
            return result
    if "dnsmasq" in line:
        result = parse_dnsmasq_dns(line)
        if result is not None:
            return result
    if "subtype=" in line and "dns" in line.lower():
        return parse_fortigate_dns(line)
    return None


# ──────────────────────────────────────────────────────────────────
#  Firewall yönetim erişimi (F3) — marka bağımsız
#  Firewall'un admin paneline/SSH'ına giriş denemeleri — firewall ele
#  geçirilirse tüm ağ korumasız kalır (CIS Controls v8 Control 8.11,
#  NIST SP 800-92 §3.2). Tüm formatlar gerçek dokümantasyon/forum
#  örnekleriyle doğrulandı (F3 araştırması).
# ──────────────────────────────────────────────────────────────────

# FortiGate — docs.fortinet.com doğrulandı:
# type="event" subtype="system" logdesc="Admin login successful" user="admin"
# srcip=... action="login" status="success"|"failed"
def parse_fortigate_admin_access(line: str) -> Optional[NormalizedLog]:
    if "subtype=" not in line or "system" not in line.lower():
        return None
    kv = {k: v.strip('"') for k, v in _FORTI_KV_RE.findall(line)}
    if kv.get("subtype", "").lower() != "system":
        return None
    if kv.get("action", "").lower() != "login":
        return None

    src_ip = kv.get("srcip")
    if not src_ip:
        return None

    status  = kv.get("status", "").lower()
    success = status == "success"
    user    = kv.get("user", "")
    event_action = "fw_admin_login_success" if success else "fw_admin_login_failure"
    severity     = "info" if success else "warning"

    msg = f"FortiGate admin login {'success' if success else 'failure'}: user={user} from {src_ip}"

    return _make_log(
        source_type = LogSourceType.FORTIGATE,
        observer_hostname = kv.get("devname", "fortigate"),
        event_action  = event_action,
        severity    = severity,
        event_category    = LogCategory.AUTHENTICATION,
        message     = msg,
        raw_content = line,
        source_ip      = src_ip,
        tags        = ["fw_admin", "fortigate", status],
        extra       = {"user": user, "method": kv.get("method", "")},
    )


# Cisco ASA — Cisco syslog mesaj referansı doğrulandı:
# %ASA-6-605005 Login permitted / %ASA-6-605004 Login denied
# %ASA-6-611101 User authentication succeeded / %ASA-6-611102 ... failed
# Not: severity rakamı cihaz config'ine göre değişebilir, \d ile esnek bırakıldı.
_ASA_LOGIN_RE = re.compile(
    r'%ASA-\d-(?P<code>605005|605004):\s+Login (?:permitted|denied) from\s+'
    r'(?P<ip>[\d.]+)/\d+\s+to\s+\S+\s+for user\s+"?(?P<user>[^"\s]+)"?'
)
_ASA_AUTH_RE = re.compile(
    r'%ASA-\d-(?P<code>611101|611102):\s+User authentication (?:succeeded|failed):?'
    r'(?:.*?IP address:\s*(?P<ip>[\d.]+),)?\s*Uname:\s*(?P<user>\S+)'
)


def parse_cisco_asa_admin_access(line: str) -> Optional[NormalizedLog]:
    m = _ASA_LOGIN_RE.search(line) or _ASA_AUTH_RE.search(line)
    if not m:
        return None

    code = m.group("code")
    ip   = m.groupdict().get("ip")
    user = m.group("user")
    success = code in ("605005", "611101")
    event_action = "fw_admin_login_success" if success else "fw_admin_login_failure"
    severity     = "info" if success else "warning"

    msg = f"Cisco ASA admin login {'success' if success else 'failure'}: user={user}"
    if ip:
        msg += f" from {ip}"

    hm = _ASA_HOST_RE.search(line)
    observer_hostname = hm.group(1) if hm else "cisco-asa"

    return _make_log(
        source_type = LogSourceType.CISCO_ASA,
        observer_hostname = observer_hostname,
        event_action  = event_action,
        severity    = severity,
        event_category    = LogCategory.AUTHENTICATION,
        message     = msg,
        raw_content = line,
        source_ip      = ip,
        tags        = ["fw_admin", "cisco_asa", f"asa_code:{code}"],
        extra       = {"user": user, "asa_code": code},
    )


# pfSense/OPNsense webConfigurator (php-fpm) — Netgate forum/dokümantasyon doğrulandı:
# "Successful login for user 'admin' from: 10.0.0.4"
# "webConfigurator authentication error for user 'admin' from: 10.0.0.4"
# Not: pfSense ve OPNsense bu logu birebir aynı formatta üretir, satırdan
# marka ayırt edilemez — OPNSENSE varsayılan olarak kullanılır (lab'da aktif olan).
_PFSENSE_LOGIN_OK_RE = re.compile(
    r"php-fpm(?:\[\d+\])?:\s+/index\.php:\s+Successful login for user '(?P<user>[^']+)'"
    r"\s+from:\s*(?P<ip>[\d.]+)"
)
_PFSENSE_LOGIN_FAIL_RE = re.compile(
    r"php-fpm(?:\[\d+\])?:\s+/index\.php:\s+webConfigurator authentication error "
    r"for user '(?P<user>[^']+)'\s+from:\s*(?P<ip>[\d.]+)"
)
_PFSENSE_HOST_RE = re.compile(r'\w+\s+\d+\s+[\d:]+\s+(\S+)\s+php-fpm')


def parse_pfsense_admin_access(line: str) -> Optional[NormalizedLog]:
    m = _PFSENSE_LOGIN_OK_RE.search(line)
    success = True
    if not m:
        m = _PFSENSE_LOGIN_FAIL_RE.search(line)
        success = False
    if not m:
        return None

    user, ip = m.group("user"), m.group("ip")
    event_action = "fw_admin_login_success" if success else "fw_admin_login_failure"
    severity     = "info" if success else "warning"

    hm = _PFSENSE_HOST_RE.search(line)
    observer_hostname = hm.group(1) if hm else "opnsense"

    msg = f"pfSense/OPNsense webgui login {'success' if success else 'failure'}: user={user} from {ip}"

    return _make_log(
        source_type = LogSourceType.OPNSENSE,
        observer_hostname = observer_hostname,
        event_action  = event_action,
        severity    = severity,
        event_category    = LogCategory.AUTHENTICATION,
        message     = msg,
        raw_content = line,
        source_ip      = ip,
        tags        = ["fw_admin", "opnsense"],
        extra       = {"user": user},
    )


# VyOS — standart sshd Accepted/Failed (OpenSSH). VyOS yönetim erişimi SSH
# üzerinden olduğu için bu, router admin erişiminin kendisidir.
_VYOS_SSH_ACCEPTED_RE = re.compile(
    r'sshd(?:\[\d+\])?:\s+Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+'
    r'(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)'
)
_VYOS_SSH_FAILED_RE = re.compile(
    r'sshd(?:\[\d+\])?:\s+Failed\s+(?P<method>\S+)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+'
    r'from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)'
)
_VYOS_SSH_HOST_RE = re.compile(r'\w+\s+\d+\s+[\d:]+\s+(\S+)\s+sshd')


def parse_vyos_admin_access(line: str) -> Optional[NormalizedLog]:
    m = _VYOS_SSH_ACCEPTED_RE.search(line)
    success = True
    if not m:
        m = _VYOS_SSH_FAILED_RE.search(line)
        success = False
    if not m:
        return None

    user, ip, port, method = m.group("user"), m.group("ip"), m.group("port"), m.group("method")
    event_action = "fw_admin_login_success" if success else "fw_admin_login_failure"
    severity     = "info" if success else "warning"

    hm = _VYOS_SSH_HOST_RE.search(line)
    observer_hostname = hm.group(1) if hm else "vyos"

    msg = f"VyOS SSH login {'success' if success else 'failure'}: user={user} from {ip}"

    return _make_log(
        source_type = LogSourceType.VYOS,
        observer_hostname = observer_hostname,
        event_action  = event_action,
        severity    = severity,
        event_category    = LogCategory.AUTHENTICATION,
        message     = msg,
        raw_content = line,
        source_ip      = ip,
        source_port    = int(port),
        tags        = ["fw_admin", "vyos"],
        extra       = {"user": user, "method": method},
    )


def parse_fw_admin_access(line: str) -> Optional[NormalizedLog]:
    """Marka bağımsız firewall yönetim erişimi dispatcher (F3)."""
    if "subtype=" in line and "system" in line.lower():
        result = parse_fortigate_admin_access(line)
        if result is not None:
            return result
    if "%ASA-" in line:
        result = parse_cisco_asa_admin_access(line)
        if result is not None:
            return result
    if "php-fpm" in line and "index.php" in line:
        result = parse_pfsense_admin_access(line)
        if result is not None:
            return result
    if "sshd" in line:
        result = parse_vyos_admin_access(line)
        if result is not None:
            return result
    return None


# ──────────────────────────────────────────────────────────────────
#  Otomatik tespit + parse
# ──────────────────────────────────────────────────────────────────

def detect_and_parse(line: str) -> Optional[NormalizedLog]:
    """Firewall log satırını otomatik tespit et ve parse et."""
    # F3 yönetim erişimi en önce kontrol edilir — %ASA-/type=system gibi
    # genel pattern'ler diğer parser'lara (parse_cisco_asa, parse_fortigate)
    # düşmeden önce admin login olaylarını yakalamalı.
    admin_result = parse_fw_admin_access(line)
    if admin_result is not None:
        return admin_result
    if "filterlog[" in line:
        return parse_opnsense(line)
    if "filterlog:" in line:
        return parse_pfsense(line)
    if "%ASA-" in line:
        return parse_cisco_asa(line)
    dhcp_result = parse_dhcp_syslog(line)
    if dhcp_result is not None:
        return dhcp_result
    dns_result = parse_dns_resolver_syslog(line)
    if dns_result is not None:
        return dns_result
    if "type=traffic" in line or "type=utm" in line:
        return parse_fortigate(line)
    if "kernel:" in line and "SRC=" in line and "DST=" in line:
        return parse_vyos(line)
    return None
