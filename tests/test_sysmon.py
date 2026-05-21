"""
Sysmon / Windows HIDS genişletme testleri (U2).

evtx_parser yeni EID'leri, parsers.windows → NormalizedLog dönüşümü,
routes/evtx normalized_log yazımı.
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from server.evtx_parser import _parse_record_xml, parse_evtx_xml_strings
from server.parsers.windows import to_normalized_log
from shared.models import LogCategory, LogSourceType

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_TS = "2024-01-15T10:00:00.000000Z"


# ── XML şablon yardımcısı ───────────────────────────────────────────────────

def _evt_xml(eid: int, computer: str, data_fields: dict, system_time: str = _TS) -> str:
    data_xml = "\n".join(
        f'<Data Name="{k}">{v}</Data>' for k, v in data_fields.items()
    )
    return f"""<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="{_NS}">
  <System>
    <EventID>{eid}</EventID>
    <TimeCreated SystemTime="{system_time}"/>
    <Computer>{computer}</Computer>
  </System>
  <EventData>
    {data_xml}
  </EventData>
</Event>"""


# ─────────────────────────────────────────────────────────────────────────────
#  1. Mevcut EID'ler — gerileme testi
# ─────────────────────────────────────────────────────────────────────────────

class TestExistingEids:
    def test_4624_logon_success(self):
        xml = _evt_xml(4624, "WIN-PC", {
            "TargetUserName": "alice", "IpAddress": "10.0.0.5",
            "LogonType": "3",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_logon_success"
        assert rec["source_ip"] == "10.0.0.5"

    def test_4624_service_logon_filtered(self):
        xml = _evt_xml(4624, "WIN-PC", {
            "TargetUserName": "SYSTEM", "IpAddress": "-",
            "LogonType": "5",
        })
        assert _parse_record_xml(xml) is None

    def test_4625_logon_failure(self):
        xml = _evt_xml(4625, "WIN-PC", {
            "TargetUserName": "bob", "IpAddress": "192.168.1.100",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_logon_failure"
        assert rec["severity"] == "warning"

    def test_4688_process_create(self):
        xml = _evt_xml(4688, "WIN-PC", {
            "SubjectUserName": "alice",
            "NewProcessName": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_process_create"

    def test_4688_malware_process_is_critical(self):
        xml = _evt_xml(4688, "WIN-PC", {
            "SubjectUserName": "user",
            "NewProcessName": r"C:\Temp\mimikatz.exe",
            "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["severity"] == "critical"


# ─────────────────────────────────────────────────────────────────────────────
#  2. Yeni Windows Security EID'leri
# ─────────────────────────────────────────────────────────────────────────────

class TestNewSecurityEids:
    def test_4648_explicit_logon(self):
        xml = _evt_xml(4648, "WIN-DC", {
            "SubjectUserName": "alice",
            "AccountName": "administrator",
            "ServerName": "fileserver",
            "ProcessName": r"C:\Windows\System32\runas.exe",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_explicit_logon"
        assert rec["severity"] == "warning"
        assert "alice" in rec["message"]
        assert "administrator" in rec["message"]

    def test_4720_user_created(self):
        xml = _evt_xml(4720, "WIN-DC", {
            "TargetUserName": "backdoor_user",
            "SubjectUserName": "attacker",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_user_created"
        assert rec["severity"] == "warning"
        assert "backdoor_user" in rec["message"]

    def test_4732_group_member_added(self):
        xml = _evt_xml(4732, "WIN-DC", {
            "MemberName": r"DOMAIN\evil_user",
            "TargetUserName": "Administrators",
            "SubjectUserName": "admin",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_group_member_added"
        assert "Administrators" in rec["message"]

    def test_4768_kerberos_tgt_normal(self):
        xml = _evt_xml(4768, "WIN-DC", {
            "TargetUserName": "alice",
            "TargetDomainName": "corp.local",
            "IpAddress": "10.0.0.50",
            "Status": "0x0",
            "TicketEncryptionType": "0x12",  # AES256 — normal
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_kerberos_tgt"
        assert rec["severity"] == "info"
        assert "WEAK_ENCRYPTION" not in rec["message"]

    def test_4768_kerberos_tgt_downgrade(self):
        xml = _evt_xml(4768, "WIN-DC", {
            "TargetUserName": "alice",
            "TargetDomainName": "corp.local",
            "IpAddress": "10.0.0.50",
            "Status": "0x0",
            "TicketEncryptionType": "0x17",  # RC4 — downgrade
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["severity"] == "warning"
        assert "WEAK_ENCRYPTION" in rec["message"]

    def test_4768_kerberos_tgt_failure(self):
        xml = _evt_xml(4768, "WIN-DC", {
            "TargetUserName": "alice",
            "TargetDomainName": "corp.local",
            "IpAddress": "10.0.0.50",
            "Status": "0x18",  # Yanlış parola
            "TicketEncryptionType": "0x12",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["severity"] == "warning"

    def test_4769_kerberoasting(self):
        xml = _evt_xml(4769, "WIN-DC", {
            "TargetUserName": "alice@corp.local",
            "ServiceName": "MSSQLSvc/sqlserver",
            "IpAddress": "10.0.0.100",
            "TicketEncryptionType": "0x17",  # RC4 — kerberoasting
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_kerberos_service"
        assert rec["severity"] == "warning"
        assert "KERBEROAST" in rec["message"]

    def test_4769_normal_aes_is_info(self):
        xml = _evt_xml(4769, "WIN-DC", {
            "TargetUserName": "alice@corp.local",
            "ServiceName": "HTTP/webserver",
            "IpAddress": "10.0.0.100",
            "TicketEncryptionType": "0x12",  # AES256
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["severity"] == "info"
        assert "KERBEROAST" not in rec["message"]


# ─────────────────────────────────────────────────────────────────────────────
#  3. Sysmon EID'leri
# ─────────────────────────────────────────────────────────────────────────────

class TestSysmonEids:
    def test_eid1_normal_process(self):
        xml = _evt_xml(1, "WIN-WS", {
            "Image": r"C:\Windows\explorer.exe",
            "CommandLine": "explorer.exe",
            "ParentImage": r"C:\Windows\System32\userinit.exe",
            "User": "alice",
            "Hashes": "SHA256=abc",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_sysmon_process"
        assert rec["severity"] == "info"
        assert "explorer.exe" in rec["message"]

    def test_eid1_lolbas_suspicious_parent(self):
        xml = _evt_xml(1, "WIN-WS", {
            "Image": r"C:\Windows\System32\powershell.exe",
            "CommandLine": "powershell.exe -enc BASE64PAYLOAD",
            "ParentImage": r"C:\Users\alice\Downloads\invoice.docm",  # Macro
            "User": "alice",
            "Hashes": "",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["severity"] == "warning"

    def test_eid1_known_malware_is_critical(self):
        xml = _evt_xml(1, "WIN-WS", {
            "Image": r"C:\Temp\mimikatz.exe",
            "CommandLine": "mimikatz.exe",
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "User": "alice",
            "Hashes": "",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["severity"] == "critical"

    def test_eid3_normal_browser(self):
        xml = _evt_xml(3, "WIN-WS", {
            "Image": r"C:\Program Files\Chrome\chrome.exe",
            "SourceIp": "192.168.1.50",
            "DestinationIp": "142.250.185.100",
            "DestinationPort": "443",
            "Protocol": "tcp",
            "User": "alice",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_sysmon_network"
        assert rec["severity"] == "info"
        assert rec["destination_ip"] == "142.250.185.100"
        assert rec["destination_port"] == 443

    def test_eid3_lolbas_powershell_outbound_is_warning(self):
        xml = _evt_xml(3, "WIN-WS", {
            "Image": r"C:\Windows\System32\powershell.exe",
            "SourceIp": "192.168.1.50",
            "DestinationIp": "185.220.101.50",
            "DestinationPort": "4444",
            "Protocol": "tcp",
            "User": "alice",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["severity"] == "warning"

    def test_eid10_lsass_is_critical(self):
        xml = _evt_xml(10, "WIN-WS", {
            "SourceImage": r"C:\Temp\mimikatz.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1010",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_sysmon_proc_access"
        assert rec["severity"] == "critical"
        assert "lsass.exe" in rec["message"]

    def test_eid10_non_lsass_is_warning(self):
        xml = _evt_xml(10, "WIN-WS", {
            "SourceImage": r"C:\Program Files\AV\aveng.exe",
            "TargetImage": r"C:\Program Files\App\app.exe",
            "GrantedAccess": "0x40",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["severity"] == "warning"

    def test_eid22_normal_browser_dns(self):
        xml = _evt_xml(22, "WIN-WS", {
            "Image": r"C:\Program Files\Chrome\chrome.exe",
            "QueryName": "google.com",
            "QueryStatus": "0",
            "QueryResults": "172.217.168.46",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["event_action"] == "windows_sysmon_dns"
        assert rec["severity"] == "info"
        assert "google.com" in rec["message"]

    def test_eid22_powershell_dns_is_warning(self):
        xml = _evt_xml(22, "WIN-WS", {
            "Image": r"C:\Windows\System32\powershell.exe",
            "QueryName": "c2.evil.com",
            "QueryStatus": "0",
            "QueryResults": "1.2.3.4",
        })
        rec = _parse_record_xml(xml)
        assert rec is not None
        assert rec["severity"] == "warning"

    def test_unknown_eid_returns_none(self):
        xml = _evt_xml(9999, "WIN-WS", {"Data": "value"})
        assert _parse_record_xml(xml) is None


# ─────────────────────────────────────────────────────────────────────────────
#  4. to_normalized_log dönüşümü
# ─────────────────────────────────────────────────────────────────────────────

class TestToNormalizedLog:
    def _rec(self, **kw):
        base = {
            "event_action":      "windows_sysmon_proc_access",
            "severity":          "critical",
            "username":          None,
            "source_ip":         None,
            "observer_hostname": "WIN-WS",
            "message":           "Test message",
            "occurred_at":       "2024-01-15T10:00:00.000000Z",
        }
        base.update(kw)
        return base

    def test_basic_conversion(self):
        norm = to_normalized_log(self._rec())
        assert norm is not None
        assert norm.event_action == "windows_sysmon_proc_access"
        assert norm.source_type == LogSourceType.WINDOWS
        assert norm.event_category == LogCategory.INTRUSION
        assert norm.severity == "critical"

    def test_missing_event_action_returns_none(self):
        assert to_normalized_log({}) is None

    def test_logon_is_authentication_category(self):
        norm = to_normalized_log(self._rec(event_action="windows_logon_failure"))
        assert norm is not None
        assert norm.event_category == LogCategory.AUTHENTICATION

    def test_sysmon_network_is_network_category(self):
        norm = to_normalized_log(self._rec(event_action="windows_sysmon_network"))
        assert norm is not None
        assert norm.event_category == LogCategory.NETWORK

    def test_destination_port_conversion(self):
        norm = to_normalized_log(self._rec(
            event_action="windows_sysmon_network",
            destination_ip="1.2.3.4",
            destination_port=443,
        ))
        assert norm is not None
        assert norm.destination_port == 443

    def test_naive_datetime_gets_utc(self):
        norm = to_normalized_log(self._rec(occurred_at="2024-01-15T10:00:00"))
        assert norm is not None
        assert norm.timestamp.tzinfo is not None

    def test_tags_contain_windows_evtx(self):
        norm = to_normalized_log(self._rec())
        assert "windows" in norm.tags
        assert "evtx" in norm.tags

    def test_observer_hostname_preserved(self):
        norm = to_normalized_log(self._rec(observer_hostname="DC-01"))
        assert norm.observer_hostname == "DC-01"


# ─────────────────────────────────────────────────────────────────────────────
#  5. parse_evtx_xml_strings toplu test
# ─────────────────────────────────────────────────────────────────────────────

class TestParseEvtxXmlStrings:
    def test_multiple_events(self):
        xmls = [
            _evt_xml(4625, "WIN-PC", {"TargetUserName": "alice", "IpAddress": "10.0.0.1"}),
            _evt_xml(1, "WIN-PC", {
                "Image": r"C:\Windows\cmd.exe",
                "CommandLine": "cmd.exe",
                "ParentImage": r"C:\Windows\explorer.exe",
                "User": "alice", "Hashes": "",
            }),
            _evt_xml(10, "WIN-PC", {
                "SourceImage": r"C:\mimikatz.exe",
                "TargetImage": r"C:\Windows\System32\lsass.exe",
                "GrantedAccess": "0x1010",
            }),
        ]
        results = parse_evtx_xml_strings(xmls)
        assert len(results) == 3
        actions = {r["event_action"] for r in results}
        assert "windows_logon_failure" in actions
        assert "windows_sysmon_process" in actions
        assert "windows_sysmon_proc_access" in actions

    def test_empty_list(self):
        assert parse_evtx_xml_strings([]) == []

    def test_malformed_xml_skipped(self):
        xmls = [
            "not valid xml",
            _evt_xml(4625, "WIN-PC", {"TargetUserName": "bob", "IpAddress": "1.2.3.4"}),
        ]
        results = parse_evtx_xml_strings(xmls)
        assert len(results) == 1

    def test_unknown_eid_skipped(self):
        xmls = [_evt_xml(9999, "WIN-PC", {"Data": "x"})]
        assert parse_evtx_xml_strings(xmls) == []


# ─────────────────────────────────────────────────────────────────────────────
#  6. clean_ip yardımcısı
# ─────────────────────────────────────────────────────────────────────────────

class TestCleanIp:
    def test_dash_returns_none(self):
        xml = _evt_xml(4625, "WIN-PC", {"TargetUserName": "u", "IpAddress": "-"})
        rec = _parse_record_xml(xml)
        assert rec["source_ip"] is None

    def test_empty_returns_none(self):
        xml = _evt_xml(4625, "WIN-PC", {"TargetUserName": "u", "IpAddress": ""})
        rec = _parse_record_xml(xml)
        assert rec["source_ip"] is None

    def test_real_ip_preserved(self):
        xml = _evt_xml(4625, "WIN-PC", {"TargetUserName": "u", "IpAddress": "192.168.1.100"})
        rec = _parse_record_xml(xml)
        assert rec["source_ip"] == "192.168.1.100"

    def test_loopback_returns_none(self):
        xml = _evt_xml(4768, "WIN-DC", {
            "TargetUserName": "u", "TargetDomainName": "d",
            "IpAddress": "127.0.0.1", "Status": "0x0",
            "TicketEncryptionType": "0x12",
        })
        rec = _parse_record_xml(xml)
        assert rec["source_ip"] is None
