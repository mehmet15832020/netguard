"""
NetGuard — EVTX Dosya Parser

Windows .evtx formatındaki olay günlüğü dosyalarını parse eder.
Forensik analiz ve offline inceleme için kullanılır.

Gereksinim: python-evtx (pip install python-evtx)
"""

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional

logger = logging.getLogger(__name__)

_EID_MAP = {
    4624: ("windows_logon_success", "info"),
    4625: ("windows_logon_failure", "warning"),
    4688: ("windows_process_create", "info"),
}

_LOGON_TYPES = {
    "2":  "interactive",
    "3":  "network",
    "4":  "batch",
    "5":  "service",
    "7":  "unlock",
    "8":  "network_cleartext",
    "10": "remote_interactive",
    "11": "cached_interactive",
}

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _xml_text(root: ET.Element, path: str) -> str:
    el = root.find(path, {"": _NS})
    return (el.text or "").strip() if el is not None else ""


def _get_data(root: ET.Element, name: str) -> str:
    for el in root.findall(".//{%s}Data" % _NS):
        if el.get("Name") == name:
            return (el.text or "").strip()
    return ""


def _parse_record_xml(xml_str: str) -> Optional[dict]:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    try:
        eid_str = _xml_text(root, "./{%s}System/{%s}EventID" % (_NS, _NS))
        if not eid_str:
            return None
        eid = int(eid_str)
    except (ValueError, TypeError):
        return None

    if eid not in _EID_MAP:
        return None

    event_type, severity = _EID_MAP[eid]
    time_str = root.findtext(".//{%s}TimeCreated" % _NS) or ""
    el_time = root.find(".//{%s}TimeCreated" % _NS)
    occurred_at = el_time.get("SystemTime", "") if el_time is not None else ""
    if not occurred_at:
        occurred_at = datetime.now(timezone.utc).isoformat()

    computer = _xml_text(root, "./{%s}System/{%s}Computer" % (_NS, _NS))

    if eid == 4625:
        username  = _get_data(root, "TargetUserName")
        source_ip = _get_data(root, "IpAddress") or None
        if source_ip in ("-", ""):
            source_ip = None
        return {
            "event_type":  event_type,
            "severity":    severity,
            "username":    username,
            "source_ip":   source_ip,
            "source_host": computer,
            "message":     f"Windows oturum açma başarısız: kullanıcı={username}",
            "raw_data":    xml_str[:500],
            "occurred_at": occurred_at,
        }

    if eid == 4624:
        username   = _get_data(root, "TargetUserName")
        source_ip  = _get_data(root, "IpAddress") or None
        logon_type = _get_data(root, "LogonType")
        logon_label = _LOGON_TYPES.get(logon_type, logon_type)
        if source_ip in ("-", ""):
            source_ip = None
        if logon_label in ("service", "batch"):
            return None
        return {
            "event_type":  event_type,
            "severity":    severity,
            "username":    username,
            "source_ip":   source_ip,
            "source_host": computer,
            "message":     f"Windows oturum açıldı: kullanıcı={username} tür={logon_label}",
            "raw_data":    xml_str[:500],
            "occurred_at": occurred_at,
        }

    if eid == 4688:
        subject_user = _get_data(root, "SubjectUserName")
        process_name = _get_data(root, "NewProcessName")
        cmdline      = _get_data(root, "CommandLine")
        return {
            "event_type":  event_type,
            "severity":    severity,
            "username":    subject_user,
            "source_ip":   None,
            "source_host": computer,
            "message":     f"Süreç oluşturuldu: {process_name}",
            "raw_data":    f"EventID=4688 user={subject_user} process={process_name} cmd={cmdline}"[:500],
            "occurred_at": occurred_at,
        }

    return None


def parse_evtx_bytes(data: bytes) -> list[dict]:
    """
    .evtx dosya içeriğini (bytes) parse eder.
    Her tanınan event için dict döner: event_type, severity, username, source_ip,
    source_host, message, raw_data, occurred_at.
    """
    try:
        from Evtx.Evtx import FileHeader
        from Evtx.Views import evtx_file_xml_view
    except ImportError:
        logger.error("python-evtx kurulu değil: pip install python-evtx")
        return []

    results: list[dict] = []
    try:
        fh = FileHeader(data, 0x0)
        for xml_str, record in evtx_file_xml_view(fh):
            parsed = _parse_record_xml(xml_str)
            if parsed:
                results.append(parsed)
    except Exception as exc:
        logger.warning(f"EVTX parse hatası: {exc}")
    return results


def parse_evtx_xml_strings(xml_strings: list[str]) -> list[dict]:
    """
    XML string listesinden parse eder (test ve mock için kullanılır).
    """
    results = []
    for xml_str in xml_strings:
        parsed = _parse_record_xml(xml_str)
        if parsed:
            results.append(parsed)
    return results
