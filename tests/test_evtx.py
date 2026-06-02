"""EVTX parser ve upload endpoint testleri."""

import io
import textwrap
import pytest
from fastapi.testclient import TestClient
from server.main import app
from server.auth import create_access_token
from server.evtx_parser import parse_evtx_xml_strings, _parse_record_xml

client = TestClient(app)


def _auth():
    token = create_access_token(username="admin", role="admin")
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------ #
#  evtx_parser — XML string parse
# ------------------------------------------------------------------ #

def _make_xml(eid: int, **fields) -> str:
    data_elements = "\n".join(
        f'<Data Name="{k}">{v}</Data>' for k, v in fields.items()
    )
    return textwrap.dedent(f"""\
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <EventID>{eid}</EventID>
            <TimeCreated SystemTime="2024-01-15T10:30:00.000Z"/>
            <Computer>WIN-SERVER01</Computer>
          </System>
          <EventData>
            {data_elements}
          </EventData>
        </Event>
    """)


class TestParseRecordXml:
    def test_4625_logon_failure(self):
        xml = _make_xml(4625, TargetUserName="jdoe", IpAddress="10.0.0.5")
        result = _parse_record_xml(xml)
        assert result is not None
        assert result["event_action"] == "windows_logon_failure"
        assert result["severity"] == "warning"
        assert result["username"] == "jdoe"
        assert result["source_ip"] == "10.0.0.5"
        assert "WIN-SERVER01" in result["observer_hostname"]

    def test_4624_logon_success_interactive(self):
        xml = _make_xml(4624, TargetUserName="admin", IpAddress="192.168.1.1", LogonType="2")
        result = _parse_record_xml(xml)
        assert result is not None
        assert result["event_action"] == "windows_logon_success"
        assert result["username"] == "admin"

    def test_4624_service_logon_ignored(self):
        xml = _make_xml(4624, TargetUserName="svc_app", IpAddress="-", LogonType="5")
        result = _parse_record_xml(xml)
        assert result is None  # service logon → gürültü, göz ardı edilir

    def test_4624_batch_logon_ignored(self):
        xml = _make_xml(4624, TargetUserName="batch_user", IpAddress="-", LogonType="4")
        result = _parse_record_xml(xml)
        assert result is None

    def test_4688_process_create(self):
        xml = _make_xml(
            4688,
            SubjectUserName="administrator",
            NewProcessName=r"C:\Windows\System32\cmd.exe",
            CommandLine="cmd.exe /c whoami",
        )
        result = _parse_record_xml(xml)
        assert result is not None
        assert result["event_action"] == "windows_process_create"
        assert result["username"] == "administrator"
        assert "cmd.exe" in result["message"]

    def test_unknown_event_id_ignored(self):
        xml = _make_xml(9999)  # Desteklenmeyen EID
        result = _parse_record_xml(xml)
        assert result is None

    def test_ip_dash_normalized_to_none(self):
        xml = _make_xml(4625, TargetUserName="user", IpAddress="-")
        result = _parse_record_xml(xml)
        assert result["source_ip"] is None

    def test_invalid_xml_returns_none(self):
        result = _parse_record_xml("<not valid xml")
        assert result is None

    def test_occurred_at_populated(self):
        xml = _make_xml(4625, TargetUserName="x", IpAddress="1.2.3.4")
        result = _parse_record_xml(xml)
        assert result["occurred_at"] != ""


class TestParseEvtxXmlStrings:
    def test_multiple_records(self):
        xml1 = _make_xml(4625, TargetUserName="user1", IpAddress="10.0.0.1")
        xml2 = _make_xml(4624, TargetUserName="admin", IpAddress="10.0.0.2", LogonType="2")
        xml3 = _make_xml(4688, SubjectUserName="admin", NewProcessName="powershell.exe", CommandLine="powershell")
        results = parse_evtx_xml_strings([xml1, xml2, xml3])
        assert len(results) == 3

    def test_filters_out_ignored(self):
        xml_svc  = _make_xml(4624, TargetUserName="svc", IpAddress="-", LogonType="5")
        xml_fail = _make_xml(4625, TargetUserName="user", IpAddress="1.2.3.4")
        results = parse_evtx_xml_strings([xml_svc, xml_fail])
        assert len(results) == 1
        assert results[0]["event_action"] == "windows_logon_failure"

    def test_empty_list(self):
        assert parse_evtx_xml_strings([]) == []


# ------------------------------------------------------------------ #
#  /api/v1/evtx/upload endpoint
# ------------------------------------------------------------------ #

class TestEvtxUpload:
    def test_rejects_non_evtx_file(self, tmp_db):
        data = io.BytesIO(b"not an evtx file")
        r = client.post(
            "/api/v1/evtx/upload",
            files={"file": ("security.log", data, "application/octet-stream")},
            headers=_auth(),
        )
        assert r.status_code == 400

    def test_rejects_empty_file(self, tmp_db):
        r = client.post(
            "/api/v1/evtx/upload",
            files={"file": ("security.evtx", io.BytesIO(b""), "application/octet-stream")},
            headers=_auth(),
        )
        assert r.status_code == 400

    def test_requires_auth(self, tmp_db):
        r = client.post(
            "/api/v1/evtx/upload",
            files={"file": ("security.evtx", io.BytesIO(b"\x00"), "application/octet-stream")},
        )
        assert r.status_code == 401

    def test_valid_evtx_like_bytes_returns_zero_parsed(self, tmp_db):
        # python-evtx kurulu olmayabilir — sıfır kayıt döner ama 200 almalı
        dummy = b"ElfFile\x00" + b"\x00" * 100
        r = client.post(
            "/api/v1/evtx/upload",
            files={"file": ("security.evtx", io.BytesIO(dummy), "application/octet-stream")},
            headers=_auth(),
        )
        assert r.status_code == 200
        assert "parsed" in r.json()
        assert "saved" in r.json()


class TestEvtxEvents:
    def test_list_empty(self, tmp_db):
        r = client.get("/api/v1/evtx/events", headers=_auth())
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_invalid_limit(self, tmp_db):
        r = client.get("/api/v1/evtx/events?limit=9999", headers=_auth())
        assert r.status_code == 400

    def test_invalid_event_type(self, tmp_db):
        r = client.get("/api/v1/evtx/events?event_action=ssh_failure", headers=_auth())
        assert r.status_code == 400

    def test_requires_auth(self, tmp_db):
        r = client.get("/api/v1/evtx/events")
        assert r.status_code == 401


# ------------------------------------------------------------------ #
#  N1 — Yeni EID parse testleri
# ------------------------------------------------------------------ #

class TestN1NewEIDs:

    # ── Security kanalı ──────────────────────────────────────────────

    def test_4672_sedebug_privilege_critical(self):
        xml = _make_xml(4672, SubjectUserName="attacker",
                        PrivilegeList="SeDebugPrivilege\nSeImpersonatePrivilege")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["event_action"] == "windows_special_priv"
        assert r["severity"] == "critical"
        assert "SeDebugPrivilege" in r["message"]

    def test_4672_normal_priv_warning(self):
        xml = _make_xml(4672, SubjectUserName="user", PrivilegeList="SeShutdownPrivilege")
        r = _parse_record_xml(xml)
        assert r["severity"] == "warning"

    def test_4698_task_created_non_standard(self):
        xml = _make_xml(4698, SubjectUserName="svc", TaskName=r"\EvilTask")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["event_action"] == "windows_task_created"
        assert r["severity"] == "warning"

    def test_4698_task_created_standard_path_info(self):
        xml = _make_xml(4698, SubjectUserName="system",
                        TaskName=r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan")
        r = _parse_record_xml(xml)
        assert r["severity"] == "info"

    def test_4702_task_updated(self):
        xml = _make_xml(4702, SubjectUserName="admin", TaskName=r"\BackdoorTask")
        r = _parse_record_xml(xml)
        assert r["event_action"] == "windows_task_updated"

    def test_4740_account_lockout(self):
        xml = _make_xml(4740, TargetUserName="jdoe", SubjectUserName="DC01$")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["event_action"] == "windows_account_lockout"
        assert r["severity"] == "warning"
        assert "jdoe" in r["message"]

    def test_4771_kerberos_preauth_failed(self):
        xml = _make_xml(4771, TargetUserName="admin", IpAddress="10.0.0.5", Status="0x18")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["event_action"] == "windows_kerberos_preauth_fail"
        assert r["source_ip"] == "10.0.0.5"

    def test_4776_ntlm_failure(self):
        xml = _make_xml(4776, TargetUserName="admin", Workstation="ATTACKER-PC",
                        Status="0xC000006A")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["event_action"] == "windows_ntlm_auth"
        assert r["severity"] == "warning"
        assert "failed" in r["message"]

    def test_4776_ntlm_success_info(self):
        xml = _make_xml(4776, TargetUserName="user", Workstation="CORP-PC", Status="0x0")
        r = _parse_record_xml(xml)
        assert r["severity"] == "info"

    def test_5140_admin_share_warning(self):
        xml = _make_xml(5140, SubjectUserName="attacker", ShareName=r"\\*\ADMIN$",
                        IpAddress="10.0.0.99")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["event_action"] == "windows_share_access"
        assert r["severity"] == "warning"
        assert r["source_ip"] == "10.0.0.99"

    def test_5140_normal_share_info(self):
        xml = _make_xml(5140, SubjectUserName="user", ShareName=r"\\*\shared",
                        IpAddress="192.168.1.10")
        r = _parse_record_xml(xml)
        assert r["severity"] == "info"

    def test_1102_log_cleared_critical(self):
        xml = _make_xml(1102, SubjectUserName="attacker")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["event_action"] == "windows_log_cleared"
        assert r["severity"] == "critical"
        assert "attacker" in r["message"]

    def test_4728_admin_group_critical(self):
        xml = _make_xml(4728, MemberName="CN=evil,DC=corp,DC=local",
                        TargetUserName="Domain Admins", SubjectUserName="attacker")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["severity"] == "critical"
        assert "Domain Admins" in r["message"]

    # ── Sysmon yeni kanallar ──────────────────────────────────────────

    def test_sysmon_6_unsigned_driver_critical(self):
        xml = _make_xml(6, ImageLoaded=r"C:\evil\rootkit.sys",
                        Hashes="SHA256=abc123", Signed="false")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["event_action"] == "windows_sysmon_driver_load"
        assert r["severity"] == "critical"

    def test_sysmon_6_signed_driver_info(self):
        xml = _make_xml(6, ImageLoaded=r"C:\Windows\System32\drivers\ntfs.sys",
                        Hashes="SHA256=def456", Signed="true")
        r = _parse_record_xml(xml)
        assert r["severity"] == "info"

    def test_sysmon_7_unsigned_nonsystem_dll_warning(self):
        xml = _make_xml(7, Image=r"C:\Windows\System32\svchost.exe",
                        ImageLoaded=r"C:\Users\Public\evil.dll",
                        Hashes="SHA256=aaa", Signed="false")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["event_action"] == "windows_sysmon_image_load"
        assert r["severity"] == "warning"

    def test_sysmon_7_system32_dll_info(self):
        xml = _make_xml(7, Image=r"C:\Windows\System32\notepad.exe",
                        ImageLoaded=r"C:\Windows\System32\ntdll.dll",
                        Hashes="SHA256=bbb", Signed="true")
        r = _parse_record_xml(xml)
        assert r["severity"] == "info"

    def test_sysmon_11_executable_in_temp_warning(self):
        xml = _make_xml(11, Image=r"C:\Windows\System32\cmd.exe",
                        TargetFilename=r"C:\Users\victim\AppData\Local\Temp\payload.exe")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["event_action"] == "windows_sysmon_file_create"
        assert r["severity"] == "warning"

    def test_sysmon_11_normal_file_info(self):
        xml = _make_xml(11, Image=r"C:\Program Files\App\app.exe",
                        TargetFilename=r"C:\ProgramData\App\config.ini")
        r = _parse_record_xml(xml)
        assert r["severity"] == "info"

    def test_sysmon_13_run_key_persistence_warning(self):
        xml = _make_xml(13, Image=r"C:\Windows\Temp\malware.exe",
                        TargetObject=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilPersist",
                        Details="C:\\Windows\\Temp\\malware.exe")
        r = _parse_record_xml(xml)
        assert r is not None
        assert r["event_action"] == "windows_sysmon_registry"
        assert r["severity"] == "warning"

    def test_sysmon_13_normal_registry_info(self):
        xml = _make_xml(13, Image=r"C:\Windows\regedit.exe",
                        TargetObject=r"HKLM\SOFTWARE\Microsoft\Office\16.0\Common",
                        Details="SomeValue")
        r = _parse_record_xml(xml)
        assert r["severity"] == "info"

    # ── parsers/windows.py kategori testi ───────────────────────────

    def test_new_actions_have_category(self):
        from server.parsers.windows import _ACTION_TO_CATEGORY
        new_actions = [
            "windows_special_priv", "windows_task_created", "windows_task_updated",
            "windows_account_lockout", "windows_kerberos_preauth_fail",
            "windows_ntlm_auth", "windows_share_access", "windows_log_cleared",
            "windows_sysmon_driver_load", "windows_sysmon_image_load",
            "windows_sysmon_file_create", "windows_sysmon_registry",
        ]
        for action in new_actions:
            assert action in _ACTION_TO_CATEGORY, f"Eksik kategori: {action}"

    # ── attack_chain.py STAGE_MAP testi ──────────────────────────────

    def test_new_actions_in_stage_map(self):
        from server.attack_chain import STAGE_MAP
        expected = {
            "windows_special_priv":          "execute",
            "windows_task_created":          "execute",
            "windows_account_lockout":       "weaponize",
            "windows_log_cleared":           "execute",
            "windows_share_access":          "lateral",
            "windows_kerberos_preauth_fail": "weaponize",
            "windows_ntlm_auth":             "weaponize",
            "windows_sysmon_driver_load":    "execute",
            "windows_sysmon_registry":       "execute",
        }
        for action, stage in expected.items():
            assert STAGE_MAP.get(action) == stage, f"{action}: beklenen {stage}, bulunan {STAGE_MAP.get(action)}"
