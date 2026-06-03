"""N3 — OpenCanary parser ve collector testleri."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from server.parsers.opencanary import parse_opencanary_line
from shared.models import LogCategory, LogSourceType

_TS  = "2026-06-03T14:23:45.123456+00:00"
_SRC = "203.0.113.50"
_DST = "192.168.1.100"


def _row(**kw) -> dict:
    base = {
        "dst_host": _DST,
        "dst_port": 2000,
        "utc_time": _TS,
        "logtype":  2000,
        "node_id":  "honeypot-01",
        "src_host": _SRC,
        "src_port": 54321,
        "logdata":  {},
    }
    base.update(kw)
    return base


# ──────────────────────────────────────────────── parse_opencanary_line ────

class TestParseOpencanaryLine:

    def test_ssh_basic(self):
        r = parse_opencanary_line(_row(
            logtype=2000, dst_port=2000,
            logdata={"USERNAME": "admin", "PASSWORD": "pass"},
        ))
        assert r is not None
        assert r.event_action  == "honeypot_ssh"
        assert r.source_type   == LogSourceType.OPENCANARY
        assert r.severity      == "critical"
        assert r.username      == "admin"
        assert r.source_ip     == _SRC
        assert r.destination_ip == _DST

    def test_http_honeypot(self):
        r = parse_opencanary_line(_row(logtype=3000, dst_port=3000))
        assert r is not None
        assert r.event_action == "honeypot_http"
        assert r.event_category == LogCategory.NETWORK

    def test_smb_honeypot_critical(self):
        r = parse_opencanary_line(_row(logtype=5000, dst_port=5000))
        assert r is not None
        assert r.event_action == "honeypot_smb"
        assert r.severity == "critical"

    def test_mysql_intrusion_category(self):
        r = parse_opencanary_line(_row(logtype=8001, dst_port=8001))
        assert r is not None
        assert r.event_action == "honeypot_mysql"
        assert r.event_category == LogCategory.INTRUSION

    def test_rdp_honeypot(self):
        r = parse_opencanary_line(_row(logtype=13001, dst_port=13001))
        assert r is not None
        assert r.event_action == "honeypot_rdp"

    def test_snmp_udp_protocol(self):
        r = parse_opencanary_line(_row(logtype=13000, dst_port=13000))
        assert r is not None
        assert r.network_protocol == "udp"

    def test_ftp_honeypot(self):
        r = parse_opencanary_line(_row(logtype=2100, dst_port=2100))
        assert r is not None
        assert r.event_action == "honeypot_ftp"

    def test_redis_intrusion(self):
        r = parse_opencanary_line(_row(logtype=16001, dst_port=16001))
        assert r is not None
        assert r.event_action == "honeypot_redis"
        assert r.event_category == LogCategory.INTRUSION

    def test_unknown_logtype_returns_none(self):
        assert parse_opencanary_line(_row(logtype=99999)) is None

    def test_missing_src_host_returns_none(self):
        row = _row()
        del row["src_host"]
        assert parse_opencanary_line(row) is None

    def test_missing_dst_host_returns_none(self):
        row = _row()
        del row["dst_host"]
        assert parse_opencanary_line(row) is None

    def test_severity_always_critical(self):
        for lt in [2000, 3000, 5000, 8001, 13001]:
            r = parse_opencanary_line(_row(logtype=lt))
            assert r is not None
            assert r.severity == "critical", f"logtype={lt} critical değil"

    def test_tags_include_honeypot_opencanary(self):
        r = parse_opencanary_line(_row())
        assert "honeypot" in r.tags
        assert "opencanary" in r.tags

    def test_credential_attempt_tag_when_username(self):
        r = parse_opencanary_line(_row(logdata={"USERNAME": "root"}))
        assert "credential_attempt" in r.tags

    def test_no_credential_tag_without_username(self):
        r = parse_opencanary_line(_row(logdata={}))
        assert "credential_attempt" not in r.tags

    def test_extra_contains_logdata(self):
        logdata = {"USERNAME": "test", "PASSWORD": "secret"}
        r = parse_opencanary_line(_row(logdata=logdata))
        assert r.extra["logdata"] == logdata
        assert r.extra["node_id"] == "honeypot-01"
        assert r.extra["logtype"] == 2000

    def test_node_id_as_observer_hostname(self):
        r = parse_opencanary_line(_row(node_id="canary-dc-01"))
        assert r.observer_hostname == "canary-dc-01"

    def test_all_supported_logtypes_parse(self):
        for lt in [2000, 2100, 3000, 5000, 8001, 9001, 13000, 13001, 16001, 6001, 100, 23]:
            r = parse_opencanary_line(_row(logtype=lt))
            assert r is not None, f"logtype={lt} parse edilemedi"

    def test_local_time_fallback(self):
        row = _row()
        del row["utc_time"]
        row["local_time"] = "2026-06-03 14:23:45.123456"
        r = parse_opencanary_line(row)
        assert r is not None

    def test_source_type_opencanary(self):
        r = parse_opencanary_line(_row())
        assert r.source_type == LogSourceType.OPENCANARY

    def test_ssh_authentication_category(self):
        r = parse_opencanary_line(_row(logtype=2000))
        assert r.event_category == LogCategory.AUTHENTICATION

    def test_mssql_honeypot(self):
        r = parse_opencanary_line(_row(logtype=9001, dst_port=9001))
        assert r is not None
        assert r.event_action == "honeypot_mssql"


# ──────────────────────────────────────── collect_once (unit) ────

class TestCollectOnce:

    def _write_log(self, tmp_path: Path, events: list) -> Path:
        lf = tmp_path / "opencanary.log"
        lf.write_text(
            "\n".join(json.dumps(e) for e in events) + "\n",
            encoding="utf-8",
        )
        return lf

    def test_collect_once_processes_event(self, tmp_path):
        lf = self._write_log(tmp_path, [_row()])
        saved: list = []

        import server.opencanary_collector as oc
        orig_log, orig_off, orig_ino = oc.OPENCANARY_LOG_FILE, oc._offset, oc._inode
        try:
            oc.OPENCANARY_LOG_FILE = lf
            oc._offset = 0
            oc._inode  = lf.stat().st_ino
            with patch("server.opencanary_collector.log_store") as ms, \
                 patch("server.opencanary_collector._save_offset"):
                ms.save.side_effect = saved.append
                count = oc.collect_once()
            assert count == 1
            assert saved[0].event_action == "honeypot_ssh"
        finally:
            oc.OPENCANARY_LOG_FILE, oc._offset, oc._inode = orig_log, orig_off, orig_ino

    def test_collect_once_skips_empty_file(self, tmp_path):
        lf = tmp_path / "empty.log"
        lf.write_text("")

        import server.opencanary_collector as oc
        orig_log, orig_off = oc.OPENCANARY_LOG_FILE, oc._offset
        try:
            oc.OPENCANARY_LOG_FILE = lf
            oc._offset = 0
            count = oc.collect_once()
            assert count == 0
        finally:
            oc.OPENCANARY_LOG_FILE, oc._offset = orig_log, orig_off

    def test_collect_once_missing_file_returns_zero(self, tmp_path):
        import server.opencanary_collector as oc
        orig_log = oc.OPENCANARY_LOG_FILE
        try:
            oc.OPENCANARY_LOG_FILE = tmp_path / "nonexistent.log"
            assert oc.collect_once() == 0
        finally:
            oc.OPENCANARY_LOG_FILE = orig_log

    def test_inode_change_resets_offset(self, tmp_path):
        lf = self._write_log(tmp_path, [_row()])
        saved: list = []

        import server.opencanary_collector as oc
        orig_log, orig_off, orig_ino = oc.OPENCANARY_LOG_FILE, oc._offset, oc._inode
        try:
            oc.OPENCANARY_LOG_FILE = lf
            oc._offset = 999999
            oc._inode  = 0
            with patch("server.opencanary_collector.log_store") as ms, \
                 patch("server.opencanary_collector._save_offset"):
                ms.save.side_effect = saved.append
                count = oc.collect_once()
            assert count == 1
        finally:
            oc.OPENCANARY_LOG_FILE, oc._offset, oc._inode = orig_log, orig_off, orig_ino


# ──────────────────────────────────── LogSourceType ve STAGE_MAP ────

class TestModelsAndStageMap:

    def test_opencanary_in_log_source_type(self):
        assert LogSourceType.OPENCANARY == "opencanary"

    def test_stage_map_honeypot_entries(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("honeypot_ssh")   == "weaponize"
        assert STAGE_MAP.get("honeypot_http")  == "recon"
        assert STAGE_MAP.get("honeypot_smb")   == "lateral"
        assert STAGE_MAP.get("honeypot_mysql") == "lateral"
        assert STAGE_MAP.get("honeypot_rdp")   == "lateral"
        assert STAGE_MAP.get("honeypot_snmp")  == "recon"
        assert STAGE_MAP.get("honeypot_ftp")   == "recon"
        assert STAGE_MAP.get("honeypot_redis") == "lateral"

    def test_all_honeypot_actions_in_stage_map(self):
        from server.attack_chain import STAGE_MAP
        from server.parsers.opencanary import _LOGTYPE_TO_ACTION
        for action in _LOGTYPE_TO_ACTION.values():
            assert action in STAGE_MAP, f"STAGE_MAP'de eksik: {action}"
