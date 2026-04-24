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
        assert result["event_type"] == "windows_logon_failure"
        assert result["severity"] == "warning"
        assert result["username"] == "jdoe"
        assert result["source_ip"] == "10.0.0.5"
        assert "WIN-SERVER01" in result["source_host"]

    def test_4624_logon_success_interactive(self):
        xml = _make_xml(4624, TargetUserName="admin", IpAddress="192.168.1.1", LogonType="2")
        result = _parse_record_xml(xml)
        assert result is not None
        assert result["event_type"] == "windows_logon_success"
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
        assert result["event_type"] == "windows_process_create"
        assert result["username"] == "administrator"
        assert "cmd.exe" in result["message"]

    def test_unknown_event_id_ignored(self):
        xml = _make_xml(4776)  # NTLM auth — desteklenmiyor
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
        assert results[0]["event_type"] == "windows_logon_failure"

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
        r = client.get("/api/v1/evtx/events?event_type=ssh_failure", headers=_auth())
        assert r.status_code == 400

    def test_requires_auth(self, tmp_db):
        r = client.get("/api/v1/evtx/events")
        assert r.status_code == 401
