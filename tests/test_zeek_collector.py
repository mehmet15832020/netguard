"""Zeek log collector ve parser testleri."""

import json
import pytest
from datetime import timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from server.parsers.zeek import parse_dns, parse_http, parse_conn, parse_ssl, parse_ssh, parse_notice


# ── Parser testleri ────────────────────────────────────────────────────────────

class TestParseDns:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "8.8.8.8",
            "proto": "udp",
            "query": "example.com",
            "qtype_name": "A",
            "answers": ["93.184.216.34"],
            "rcode_name": "NOERROR",
        }
        base.update(kw)
        return base

    def test_basic(self):
        log = parse_dns(self._row())
        assert log is not None
        assert log.event_action == "dns_query"
        assert log.source_ip == "192.168.1.10"
        assert "example.com" in log.message
        assert "93.184.216.34" in log.message

    def test_empty_query_returns_none(self):
        assert parse_dns(self._row(query="")) is None
        assert parse_dns(self._row(query="-")) is None

    def test_nxdomain_in_message(self):
        log = parse_dns(self._row(answers=[], rcode_name="NXDOMAIN"))
        assert log is not None
        assert "NXDOMAIN" in log.message

    def test_multiple_answers_truncated(self):
        log = parse_dns(self._row(answers=["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6"]))
        assert log is not None
        assert "6.6.6.6" not in log.message

    def test_timestamp_parsed(self):
        log = parse_dns(self._row(ts=1700000000.0))
        assert log.timestamp.tzinfo is not None
        assert log.timestamp.year >= 2023

    def test_tags(self):
        log = parse_dns(self._row())
        assert "zeek" in log.tags
        assert "dns" in log.tags


class TestParseHttp:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 54321,
            "id.resp_h": "10.0.10.2",
            "id.resp_p": 80,
            "method": "GET",
            "host": "example.com",
            "uri": "/index.html",
            "status_code": 200,
        }
        base.update(kw)
        return base

    def test_basic_get(self):
        log = parse_http(self._row())
        assert log is not None
        assert log.event_action == "web_request"
        assert log.severity == "info"
        assert "GET" in log.message
        assert "/index.html" in log.message

    def test_400_error_severity(self):
        log = parse_http(self._row(status_code=404))
        assert log.event_action == "web_client_error"
        assert log.severity == "warning"

    def test_500_error_severity(self):
        log = parse_http(self._row(status_code=500))
        assert log.event_action == "web_client_error"
        assert log.severity == "warning"

    def test_no_method_returns_none(self):
        assert parse_http(self._row(method="")) is None
        assert parse_http(self._row(method="-")) is None

    def test_ports_parsed(self):
        log = parse_http(self._row())
        assert log.source_port == 54321
        assert log.destination_port == 80

    def test_tags(self):
        log = parse_http(self._row())
        assert "zeek" in log.tags
        assert "http" in log.tags


class TestParseConn:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 45678,
            "id.resp_h": "10.0.10.2",
            "id.resp_p": 22,
            "proto": "tcp",
            "conn_state": "REJ",
            "duration": 0.1,
        }
        base.update(kw)
        return base

    def test_rejected_conn(self):
        log = parse_conn(self._row(conn_state="REJ"))
        assert log is not None
        assert log.event_action == "network_connection"
        assert log.severity == "warning"

    def test_short_sf_filtered(self):
        assert parse_conn(self._row(conn_state="SF", duration=0.5)) is None

    def test_long_sf_kept(self):
        log = parse_conn(self._row(conn_state="SF", duration=10.0))
        assert log is not None
        assert log.severity == "info"

    def test_rsto_kept(self):
        log = parse_conn(self._row(conn_state="RSTO"))
        assert log is not None
        assert log.severity == "warning"

    def test_protocol_and_ports(self):
        log = parse_conn(self._row())
        assert log.network_protocol == "tcp"
        assert log.destination_port == 22

    def test_tags(self):
        log = parse_conn(self._row())
        assert "zeek" in log.tags
        assert "conn" in log.tags


class TestParseSsl:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 443,
            "server_name": "example.com",
            "subject": "CN=example.com",
            "validation_status": "ok",
        }
        base.update(kw)
        return base

    def test_basic(self):
        log = parse_ssl(self._row())
        assert log is not None
        assert log.event_action == "ssl_connection"
        assert "example.com" in log.message

    def test_validation_failure_severity(self):
        log = parse_ssl(self._row(validation_status="certificate has expired"))
        assert log.severity == "warning"

    def test_ok_severity(self):
        log = parse_ssl(self._row(validation_status="ok"))
        assert log.severity == "info"

    def test_dash_fields_ignored(self):
        log = parse_ssl(self._row(server_name="-", subject="-"))
        assert log is not None
        assert log.message != ""

    def test_tags(self):
        log = parse_ssl(self._row())
        assert "zeek" in log.tags
        assert "ssl" in log.tags


class TestParseSsh:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 55123,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 22,
            "auth_success": False,
            "auth_attempts": 5,
        }
        base.update(kw)
        return base

    def test_failure_event_action(self):
        log = parse_ssh(self._row())
        assert log is not None
        assert log.event_action == "ssh_failure"
        assert log.severity == "info"

    def test_success_event_action(self):
        log = parse_ssh(self._row(auth_success=True, auth_attempts=1))
        assert log.event_action == "ssh_success"
        assert log.severity == "warning"

    def test_null_success_zero_attempts_skipped(self):
        assert parse_ssh(self._row(auth_success=None, auth_attempts=0)) is None

    def test_null_success_with_attempts_kept(self):
        log = parse_ssh(self._row(auth_success=None, auth_attempts=3))
        assert log is not None
        assert log.event_action == "ssh_failure"

    def test_source_ip_set(self):
        log = parse_ssh(self._row())
        assert log.source_ip == "192.168.1.100"
        assert log.destination_port == 22

    def test_authentication_category(self):
        from shared.models import LogCategory
        log = parse_ssh(self._row())
        assert log.event_category == LogCategory.AUTHENTICATION

    def test_tags(self):
        log = parse_ssh(self._row())
        assert "zeek" in log.tags
        assert "ssh" in log.tags


class TestParseNotice:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "note": "Scan::Port_Scan",
            "msg": "192.168.1.10 has scanned 25 ports",
            "src": "192.168.1.10",
            "dst": "10.0.0.1",
            "proto": "tcp",
        }
        base.update(kw)
        return base

    def test_basic(self):
        log = parse_notice(self._row())
        assert log is not None
        assert log.event_action == "zeek_scan_port_scan"
        assert log.severity == "warning"

    def test_empty_note_returns_none(self):
        assert parse_notice(self._row(note="")) is None
        assert parse_notice(self._row(note="-")) is None

    def test_message_contains_note(self):
        log = parse_notice(self._row())
        assert "Scan::Port_Scan" in log.message

    def test_intrusion_category(self):
        from shared.models import LogCategory
        log = parse_notice(self._row())
        assert log.event_category == LogCategory.INTRUSION

    def test_src_ip_mapped(self):
        log = parse_notice(self._row())
        assert log.source_ip == "192.168.1.10"

    def test_tags(self):
        log = parse_notice(self._row())
        assert "zeek" in log.tags
        assert "notice" in log.tags


# ── Collector testleri ─────────────────────────────────────────────────────────

class TestCollectOnce:
    def test_returns_zero_when_dir_missing(self, tmp_path):
        import server.zeek_collector as zc
        original = zc.ZEEK_LOG_DIR
        zc.ZEEK_LOG_DIR = tmp_path / "nonexistent"
        try:
            assert zc.collect_once() == 0
        finally:
            zc.ZEEK_LOG_DIR = original

    def test_reads_dns_log(self, tmp_path, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        rows = [
            {"ts": 1700000000.0, "id.orig_h": "10.0.0.1", "id.resp_h": "8.8.8.8",
             "proto": "udp", "query": "evil.com", "qtype_name": "A",
             "answers": ["1.2.3.4"], "rcode_name": "NOERROR"},
        ]
        (tmp_path / "dns.log").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

        saved = []
        monkeypatch.setattr(zc.db, "save_normalized_log", lambda log, tenant_id="default": saved.append(log))

        n = zc.collect_once()
        assert n == 1
        assert saved[0].event_action == "dns_query"
        assert saved[0].source_ip == "10.0.0.1"

    def test_skips_comment_lines(self, tmp_path, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        (tmp_path / "dns.log").write_text(
            "#separator \\x09\n"
            "#fields ts id.orig_h\n"
            + json.dumps({"ts": 1700000000.0, "id.orig_h": "1.2.3.4",
                          "id.resp_h": "8.8.8.8", "proto": "udp",
                          "query": "test.com", "qtype_name": "A",
                          "answers": [], "rcode_name": "NOERROR"}) + "\n"
        )

        saved = []
        monkeypatch.setattr(zc.db, "save_normalized_log", lambda log, tenant_id="default": saved.append(log))
        n = zc.collect_once()
        assert n == 1

    def test_offset_tracking(self, tmp_path, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        row = {"ts": 1700000000.0, "id.orig_h": "1.1.1.1", "id.resp_h": "8.8.8.8",
               "proto": "udp", "query": "a.com", "qtype_name": "A",
               "answers": [], "rcode_name": "NOERROR"}
        log_file = tmp_path / "dns.log"
        log_file.write_text(json.dumps(row) + "\n")

        saved = []
        monkeypatch.setattr(zc.db, "save_normalized_log", lambda log, tenant_id="default": saved.append(log))

        zc.collect_once()
        assert len(saved) == 1

        # İkinci kez çağırınca aynı satırı tekrar okumamalı
        zc.collect_once()
        assert len(saved) == 1

    def test_reads_http_log(self, tmp_path, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        row = {"ts": 1700000000.0, "id.orig_h": "10.0.0.1", "id.orig_p": 54321,
               "id.resp_h": "10.0.10.2", "id.resp_p": 80,
               "method": "GET", "host": "target.com", "uri": "/admin",
               "status_code": 403}
        (tmp_path / "http.log").write_text(json.dumps(row) + "\n")

        saved = []
        monkeypatch.setattr(zc.db, "save_normalized_log", lambda log, tenant_id="default": saved.append(log))
        n = zc.collect_once()
        assert n == 1
        assert saved[0].event_action == "web_client_error"

    def test_rotation_reset(self, tmp_path, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        row = {"ts": 1700000000.0, "id.orig_h": "1.1.1.1", "id.resp_h": "8.8.8.8",
               "proto": "udp", "query": "b.com", "qtype_name": "A",
               "answers": [], "rcode_name": "NOERROR"}
        log_file = tmp_path / "dns.log"
        content = json.dumps(row) + "\n"
        log_file.write_text(content)

        saved = []
        monkeypatch.setattr(zc.db, "save_normalized_log", lambda log, tenant_id="default": saved.append(log))
        zc.collect_once()
        assert len(saved) == 1

        # Dosya rotasyonu simüle et — daha küçük dosya
        log_file.write_text(json.dumps(row) + "\n")  # aynı içerik, offset sıfırlanmalı
        # Offset'i yapay olarak büyük yap
        key = str(log_file.resolve())
        zc._offsets[key] = 99999

        zc.collect_once()
        assert len(saved) == 2  # tekrar okur
