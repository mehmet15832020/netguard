"""Zeek log collector ve parser testleri."""

import json
import pytest
from datetime import timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from server.parsers.zeek import (
    parse_dns, parse_http, parse_conn, parse_ssl, parse_ssh, parse_notice,
    parse_x509, parse_smtp, parse_ftp, _KNOWN_BAD_JA3, _KNOWN_BAD_JA4, _KNOWN_BAD_JA4S,
)


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

    def test_high_entropy_subdomain_flagged(self):
        log = parse_dns(self._row(query="XKj3Lm9PABCDabcd12345678901234.evil.com"))
        assert log is not None
        assert "[HIGH_ENTROPY:" in log.message
        assert log.severity == "high"

    def test_normal_subdomain_no_entropy_flag(self):
        log = parse_dns(self._row(query="mail.example.com"))
        assert "[HIGH_ENTROPY:" not in log.message

    def test_long_query_flagged(self):
        long_query = "a" * 51 + ".evil.com"
        log = parse_dns(self._row(query=long_query))
        assert "[LONG_QUERY:" in log.message
        assert log.severity in ("warning", "high")

    def test_short_query_no_long_flag(self):
        log = parse_dns(self._row(query="short.com"))
        assert "[LONG_QUERY:" not in log.message

    def test_high_entropy_and_long_both_flagged(self):
        query = "XKj3Lm9PABCDabcd12345678901234EFGHijklmnop.evil.com"
        log = parse_dns(self._row(query=query))
        assert "[HIGH_ENTROPY:" in log.message
        assert "[LONG_QUERY:" in log.message

    def test_severity_high_for_entropy(self):
        log = parse_dns(self._row(query="XKj3Lm9PABCDabcd12345678901234.evil.com"))
        assert log.severity == "high"

    def test_severity_warning_for_long_only(self):
        log = parse_dns(self._row(query="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.com"))
        assert "[LONG_QUERY:" in log.message
        assert log.severity == "warning"
        assert "[HIGH_ENTROPY:" not in log.message

    def test_cdn_short_label_not_flagged(self):
        log = parse_dns(self._row(query="d3kq5j8w9x.cloudfront.net"))
        assert "[HIGH_ENTROPY:" not in log.message

    def test_dkim_selector_not_flagged(self):
        log = parse_dns(self._row(query="20231101._domainkey.example.com"))
        assert "[HIGH_ENTROPY:" not in log.message

    def test_acme_challenge_not_flagged(self):
        log = parse_dns(self._row(query="_acme-challenge.example.com"))
        assert "[HIGH_ENTROPY:" not in log.message

    def test_multi_part_tld_co_uk(self):
        log = parse_dns(self._row(query="mail.example.co.uk"))
        assert "[HIGH_ENTROPY:" not in log.message

    def test_entropy_threshold_is_4(self):
        log = parse_dns(self._row(query="d111de75b6f9f6e34256854.evil.com"))
        assert log is not None


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

    def test_ja3_stored_in_extra(self):
        ja3 = "a0e9f5d64349fb13191bc781f81f42e1"
        log = parse_ssl(self._row(ja3=ja3, ja3s="some_hash"))
        assert log is not None
        assert log.extra.get("ja3") == ja3
        assert log.extra.get("ja3s") == "some_hash"

    def test_known_bad_ja3_critical(self):
        bad_ja3 = next(iter(_KNOWN_BAD_JA3))
        log = parse_ssl(self._row(ja3=bad_ja3))
        assert log.severity == "critical"
        assert log.event_action == "tls_suspicious_fingerprint"
        assert "ja3_malware" in log.tags
        assert "KNOWN_MALWARE_JA3" in log.message

    def test_unknown_ja3_info(self):
        log = parse_ssl(self._row(ja3="aabbccddeeff00112233445566778899"))
        assert log.severity == "info"
        assert log.event_action == "ssl_connection"

    def test_dash_ja3_ignored(self):
        log = parse_ssl(self._row(ja3="-", ja3s="-"))
        assert log is not None
        assert log.extra == {}

    def test_ja3_abbreviated_in_message(self):
        log = parse_ssl(self._row(ja3="aabbccdd11223344aabbccdd11223344"))
        assert "JA3=aabbccdd" in log.message

    def test_ja4_stored_in_extra(self):
        ja4 = "t13d1516h2_8daaf6152771_aabbccdd1234"
        ja4s = "t13d_some_server_hash_1234"
        log = parse_ssl(self._row(ja4=ja4, ja4s=ja4s))
        assert log is not None
        assert log.extra.get("ja4") == ja4
        assert log.extra.get("ja4s") == ja4s

    def test_known_bad_ja4_critical(self):
        bad_ja4 = next(iter(_KNOWN_BAD_JA4))
        log = parse_ssl(self._row(ja4=bad_ja4))
        assert log.severity == "critical"
        assert log.event_action == "tls_suspicious_fingerprint"
        assert "ja4_malware" in log.tags
        assert "KNOWN_MALWARE_JA4" in log.message

    def test_unknown_ja4_info(self):
        log = parse_ssl(self._row(ja4="t13d1234h2_8daaf6152771_e5627efa2ab1"))
        assert log.severity == "info"
        assert log.event_action == "ssl_connection"

    def test_dash_ja4_ignored(self):
        log = parse_ssl(self._row(ja4="-", ja4s="-"))
        assert log.extra.get("ja4") is None
        assert log.extra.get("ja4s") is None

    def test_ja4_preferred_over_ja3_in_message(self):
        ja4 = "t13d1516h2_8daaf6152771_aabbccdd1234"
        ja3 = "aabbccdd11223344aabbccdd11223344"
        log = parse_ssl(self._row(ja4=ja4, ja3=ja3))
        assert "JA4=" in log.message
        assert "JA3=" not in log.message

    def test_bad_ja3_with_normal_ja4_shows_ja3_malware_in_message(self):
        bad_ja3 = next(iter(_KNOWN_BAD_JA3))
        ja4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"
        log = parse_ssl(self._row(ja4=ja4, ja3=bad_ja3))
        assert log.severity == "critical"
        assert "ja3_malware" in log.tags
        assert "KNOWN_MALWARE_JA3" in log.message
        assert "JA4=" in log.message

    def test_ja3_shown_when_no_ja4(self):
        log = parse_ssl(self._row(ja3="aabbccdd11223344aabbccdd11223344"))
        assert "JA3=" in log.message
        assert "JA4=" not in log.message

    def test_ja4_abbreviated_in_message(self):
        ja4 = "t13d1516h2_8daaf6152771_b0da82dd1658"
        log = parse_ssl(self._row(ja4=ja4))
        assert "JA4=t13d1516h2_8" in log.message

    def test_bad_ja4_takes_priority_over_bad_cert(self):
        bad_ja4 = next(iter(_KNOWN_BAD_JA4))
        log = parse_ssl(self._row(ja4=bad_ja4, validation_status="certificate has expired"))
        assert log.severity == "critical"
        assert log.event_action == "tls_suspicious_fingerprint"

    def test_bad_ja3_still_detected_without_ja4(self):
        bad_ja3 = next(iter(_KNOWN_BAD_JA3))
        log = parse_ssl(self._row(ja3=bad_ja3))
        assert log.severity == "critical"
        assert "ja3_malware" in log.tags

    def test_both_ja3_and_ja4_stored(self):
        ja4 = "t13d1516h2_8daaf6152771_aabbccdd1234"
        ja3 = "aabbccdd11223344aabbccdd11223344"
        log = parse_ssl(self._row(ja4=ja4, ja3=ja3))
        assert log.extra.get("ja4") == ja4
        assert log.extra.get("ja3") == ja3

    # ── JA4S (server-side fingerprint) ────────────────────────────────────────

    def test_known_bad_ja4s_high_severity(self):
        bad_ja4s = next(iter(_KNOWN_BAD_JA4S))
        log = parse_ssl(self._row(ja4s=bad_ja4s))
        assert log.severity == "high"
        assert log.event_action == "tls_suspicious_ja4s"
        assert "ja4s_malware" in log.tags
        assert "KNOWN_MALWARE_JA4S" in log.message

    def test_ja4s_stored_in_extra(self):
        ja4s = next(iter(_KNOWN_BAD_JA4S))
        log = parse_ssl(self._row(ja4s=ja4s))
        assert log.extra.get("ja4s") == ja4s

    def test_unknown_ja4s_no_detection(self):
        log = parse_ssl(self._row(ja4s="t130300_1302_aabbccdd1234"))
        assert log.event_action == "ssl_connection"
        assert "ja4s_malware" not in log.tags

    def test_double_match_ja4_and_ja4s_critical(self):
        bad_ja4  = next(iter(_KNOWN_BAD_JA4))
        bad_ja4s = next(iter(_KNOWN_BAD_JA4S))
        log = parse_ssl(self._row(ja4=bad_ja4, ja4s=bad_ja4s))
        assert log.severity == "critical"
        assert log.event_action == "tls_suspicious_fingerprint"
        assert "ja4_malware" in log.tags
        assert "ja4s_malware" in log.tags
        assert "double_fingerprint" in log.tags
        assert "DOUBLE_FINGERPRINT" in log.message
        assert log.extra.get("double_fingerprint") is True

    def test_double_match_message_contains_both(self):
        bad_ja4  = next(iter(_KNOWN_BAD_JA4))
        bad_ja4s = next(iter(_KNOWN_BAD_JA4S))
        log = parse_ssl(self._row(ja4=bad_ja4, ja4s=bad_ja4s))
        assert "KNOWN_MALWARE_JA4]" in log.message
        assert "KNOWN_MALWARE_JA4S]" in log.message

    def test_ja4s_alone_not_critical(self):
        bad_ja4s = next(iter(_KNOWN_BAD_JA4S))
        log = parse_ssl(self._row(ja4s=bad_ja4s))
        assert log.severity != "critical"

    def test_bad_ja4_takes_priority_over_bad_ja4s_alone(self):
        bad_ja4  = next(iter(_KNOWN_BAD_JA4))
        bad_ja4s = next(iter(_KNOWN_BAD_JA4S))
        log_ja4_only  = parse_ssl(self._row(ja4=bad_ja4))
        log_ja4s_only = parse_ssl(self._row(ja4s=bad_ja4s))
        assert log_ja4_only.severity  == "critical"
        assert log_ja4s_only.severity == "high"

    def test_dash_ja4s_ignored(self):
        log = parse_ssl(self._row(ja4s="-"))
        assert log.extra.get("ja4s") is None
        assert "ja4s_malware" not in log.tags

    def test_ja4s_case_insensitive(self):
        bad_ja4s = next(iter(_KNOWN_BAD_JA4S)).upper()
        log = parse_ssl(self._row(ja4s=bad_ja4s))
        assert "ja4s_malware" in log.tags

    def test_ja4s_not_shown_in_message_when_clean(self):
        log = parse_ssl(self._row(ja4s="t130300_1302_aabbccdd1234"))
        assert "JA4S=" not in log.message


class TestParseX509:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "certificate": {
                "subject": "CN=example.com,O=Example Corp",
                "issuer": "CN=Let's Encrypt Authority X3,O=Let's Encrypt",
                "not_valid_after": 1800000000.0,
            },
        }
        base.update(kw)
        return base

    def test_basic(self):
        log = parse_x509(self._row())
        assert log is not None
        assert log.event_action == "x509_certificate"
        assert "example.com" in log.message

    def test_self_signed_warning(self):
        same_cn = "CN=evil.com"
        log = parse_x509(self._row(certificate={"subject": same_cn, "issuer": same_cn}))
        assert log.severity == "warning"
        assert "SELF-SIGNED" in log.message
        assert "self_signed" in log.tags

    def test_trusted_cert_info(self):
        log = parse_x509(self._row())
        assert log.severity == "info"
        assert "self_signed" not in log.tags

    def test_extra_contains_subject_issuer(self):
        log = parse_x509(self._row())
        assert "subject" in log.extra
        assert "issuer" in log.extra
        assert log.extra["self_signed"] is False


class TestParseSmtp:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 25,
            "mailfrom": "user@example.com",
            "rcptto": ["admin@target.com"],
            "subject": "Invoice attached",
        }
        base.update(kw)
        return base

    def test_basic(self):
        log = parse_smtp(self._row())
        assert log is not None
        assert log.event_action == "smtp_session"
        assert "user@example.com" in log.message

    def test_no_mailfrom_and_rcptto_returns_none(self):
        assert parse_smtp(self._row(mailfrom="-", rcptto=[])) is None

    def test_subject_truncated(self):
        log = parse_smtp(self._row(subject="A" * 100))
        assert len(log.message) < 300

    def test_destination_port(self):
        log = parse_smtp(self._row())
        assert log.destination_port == 25

    def test_tags(self):
        log = parse_smtp(self._row())
        assert "zeek" in log.tags
        assert "smtp" in log.tags


class TestParseFtp:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "10.0.10.2",
            "id.resp_p": 21,
            "command": "RETR",
            "arg": "secret.txt",
            "reply_code": 226,
            "user": "attacker",
        }
        base.update(kw)
        return base

    def test_sensitive_command_warning(self):
        for cmd in ["RETR", "STOR", "DELE"]:
            log = parse_ftp(self._row(command=cmd))
            assert log is not None
            assert log.severity == "warning"
            assert "ftp_sensitive" in log.tags

    def test_non_sensitive_info(self):
        log = parse_ftp(self._row(command="LIST"))
        assert log.severity == "info"
        assert "ftp_sensitive" not in log.tags

    def test_empty_command_returns_none(self):
        assert parse_ftp(self._row(command="")) is None
        assert parse_ftp(self._row(command="-")) is None

    def test_message_contains_user_and_arg(self):
        log = parse_ftp(self._row())
        assert "RETR" in log.message
        assert "attacker" in log.message
        assert "secret.txt" in log.message

    def test_extra_fields(self):
        log = parse_ftp(self._row())
        assert log.extra["command"] == "RETR"
        assert log.extra["user"] == "attacker"

    def test_tags(self):
        log = parse_ftp(self._row())
        assert "zeek" in log.tags
        assert "ftp" in log.tags


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
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))

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
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))
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
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))

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
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))
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
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))
        zc.collect_once()
        assert len(saved) == 1

        # Dosya rotasyonu simüle et — daha küçük dosya
        log_file.write_text(json.dumps(row) + "\n")  # aynı içerik, offset sıfırlanmalı
        # Offset'i yapay olarak büyük yap
        key = str(log_file.resolve())
        zc._offsets[key] = 99999

        zc.collect_once()
        assert len(saved) == 2  # tekrar okur
