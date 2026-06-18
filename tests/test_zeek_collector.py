"""Zeek log collector ve parser testleri."""

import asyncio
import json
import pytest
from datetime import timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from server.parsers.zeek import (
    parse_dns, parse_http, parse_conn, parse_ssl, parse_ssh, parse_notice,
    parse_x509, parse_smtp, parse_ftp, parse_dhcp, parse_tunnel, parse_pe,
    parse_smb_mapping, parse_software, parse_ntp,
    _KNOWN_BAD_JA3, _KNOWN_BAD_JA4, _KNOWN_BAD_JA4S,
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


class TestParseDhcp:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "client_addr": "192.168.1.50",
            "server_addr": "192.168.1.1",
            "mac": "aa:bb:cc:dd:ee:ff",
            "host_name": "DESKTOP-ABC123",
            "assigned_addr": "192.168.1.50",
            "lease_time": 86400.0,
            "msg_types": ["REQUEST", "ACK"],
        }
        base.update(kw)
        return base

    def test_basic(self):
        log = parse_dhcp(self._row())
        assert log is not None
        assert log.event_action == "dhcp_lease"
        assert log.source_ip == "192.168.1.50"
        assert log.destination_ip == "192.168.1.1"
        assert "aa:bb:cc:dd:ee:ff" in log.message
        assert "DESKTOP-ABC123" in log.message

    def test_no_mac_returns_none(self):
        assert parse_dhcp(self._row(mac="")) is None
        assert parse_dhcp(self._row(mac="-")) is None

    def test_no_assigned_addr_falls_back_to_client_addr(self):
        log = parse_dhcp(self._row(assigned_addr="-"))
        assert log is not None
        assert log.source_ip == "192.168.1.50"

    def test_no_ip_at_all_returns_none(self):
        assert parse_dhcp(self._row(assigned_addr="-", client_addr="-")) is None

    def test_extra_fields(self):
        log = parse_dhcp(self._row())
        assert log.extra["mac"] == "aa:bb:cc:dd:ee:ff"
        assert log.extra["host_name"] == "DESKTOP-ABC123"
        assert log.extra["lease_time"] == 86400.0
        assert log.extra["msg_types"] == ["REQUEST", "ACK"]

    def test_missing_hostname_empty_string(self):
        log = parse_dhcp(self._row(host_name="-"))
        assert log.extra["host_name"] == ""

    def test_nak_severity_warning(self):
        log = parse_dhcp(self._row(msg_types=["DISCOVER", "NAK"]))
        assert log.severity == "warning"

    def test_ack_severity_info(self):
        log = parse_dhcp(self._row(msg_types=["REQUEST", "ACK"]))
        assert log.severity == "info"

    def test_msg_types_as_comma_string(self):
        log = parse_dhcp(self._row(msg_types="REQUEST,ACK"))
        assert log.extra["msg_types"] == ["REQUEST", "ACK"]

    def test_tags(self):
        log = parse_dhcp(self._row())
        assert "zeek" in log.tags
        assert "dhcp" in log.tags

    def test_network_category(self):
        from shared.models import LogCategory
        log = parse_dhcp(self._row())
        assert log.event_category == LogCategory.NETWORK


class TestParseTunnel:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 0,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 0,
            "tunnel_type": "Tunnel::GRE",
            "action": "Tunnel::DISCOVER",
        }
        base.update(kw)
        return base

    def test_basic(self):
        log = parse_tunnel(self._row())
        assert log is not None
        assert log.event_action == "network_tunnel_detected"
        assert log.source_ip == "192.168.1.10"
        assert log.destination_ip == "10.0.0.5"

    def test_no_tunnel_type_returns_none(self):
        assert parse_tunnel(self._row(tunnel_type="")) is None
        assert parse_tunnel(self._row(tunnel_type="-")) is None

    def test_tunnel_type_prefix_stripped(self):
        log = parse_tunnel(self._row(tunnel_type="Tunnel::TEREDO"))
        assert log.extra["tunnel_type"] == "TEREDO"

    def test_action_prefix_stripped(self):
        log = parse_tunnel(self._row(action="Tunnel::CLOSE"))
        assert log.extra["action"] == "CLOSE"

    def test_missing_action_defaults_unknown(self):
        log = parse_tunnel(self._row(action="-"))
        assert log.extra["action"] == "UNKNOWN"

    def test_high_risk_type_discover_is_warning(self):
        for t in ["Tunnel::GRE", "Tunnel::AYIYA", "Tunnel::TEREDO", "Tunnel::SOCKS", "Tunnel::HTTP"]:
            log = parse_tunnel(self._row(tunnel_type=t, action="Tunnel::DISCOVER"))
            assert log.severity == "warning", f"{t} beklenen warning"

    def test_low_risk_type_discover_is_info(self):
        for t in ["Tunnel::IP", "Tunnel::VXLAN", "Tunnel::GTPv1"]:
            log = parse_tunnel(self._row(tunnel_type=t, action="Tunnel::DISCOVER"))
            assert log.severity == "info", f"{t} beklenen info"

    def test_close_action_always_info_even_high_risk_type(self):
        log = parse_tunnel(self._row(tunnel_type="Tunnel::GRE", action="Tunnel::CLOSE"))
        assert log.severity == "info"

    def test_expire_action_always_info(self):
        log = parse_tunnel(self._row(tunnel_type="Tunnel::GRE", action="Tunnel::EXPIRE"))
        assert log.severity == "info"

    def test_tags_include_tunnel_type(self):
        log = parse_tunnel(self._row(tunnel_type="Tunnel::GRE"))
        assert "zeek" in log.tags
        assert "tunnel" in log.tags
        assert "gre" in log.tags

    def test_network_category(self):
        from shared.models import LogCategory
        log = parse_tunnel(self._row())
        assert log.event_category == LogCategory.NETWORK

    def test_message_contains_type_and_ips(self):
        log = parse_tunnel(self._row())
        assert "GRE" in log.message
        assert "192.168.1.10" in log.message
        assert "10.0.0.5" in log.message


class TestParsePe:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "id": "FtestUID123",
            "machine": "AMD64",
            "compile_ts": "2020-09-19T00:10:08.000000Z",
            "os": "Windows",
            "subsystem": "WINDOWS_GUI",
            "is_exe": True,
            "is_64bit": True,
            "uses_aslr": True,
            "uses_dep": True,
            "uses_code_integrity": False,
            "uses_seh": True,
            "has_import_table": True,
            "has_export_table": False,
            "has_cert_table": True,
            "has_debug_data": False,
            "section_names": [".text", ".rdata", ".data", ".rsrc", ".reloc"],
        }
        base.update(kw)
        return base

    def test_basic(self):
        log = parse_pe(self._row())
        assert log is not None
        assert log.event_action == "pe_metadata"
        assert "AMD64" in log.message
        assert "64-bit" in log.message

    def test_no_fuid_returns_none(self):
        assert parse_pe(self._row(id="")) is None
        assert parse_pe(self._row(id="-")) is None

    def test_signed_standard_sections_info_severity(self):
        log = parse_pe(self._row())
        assert log.severity == "info"
        assert "unsigned" not in log.tags
        assert "packed_indicator" not in log.tags

    def test_unsigned_with_nonstandard_sections_is_warning(self):
        log = parse_pe(self._row(has_cert_table=False, section_names=[".text", ".UPX0", ".UPX1"]))
        assert log.severity == "warning"
        assert "unsigned" in log.tags
        assert "packed_indicator" in log.tags
        assert "UNSIGNED+PACKED_INDICATOR" in log.message

    def test_unsigned_with_standard_sections_stays_info(self):
        """Unsigned ama standart section'lar — tek başına yetersiz sinyal (çok yaygın FP)."""
        log = parse_pe(self._row(has_cert_table=False))
        assert log.severity == "info"
        assert "unsigned" in log.tags
        assert "packed_indicator" not in log.tags

    def test_signed_with_nonstandard_sections_stays_info(self):
        log = parse_pe(self._row(has_cert_table=True, section_names=[".text", ".weird_section"]))
        assert log.severity == "info"
        assert "packed_indicator" in log.tags
        assert "unsigned" not in log.tags

    def test_section_names_as_comma_string(self):
        log = parse_pe(self._row(section_names=".text,.rdata,.data"))
        assert log.extra["section_names"] == [".text", ".rdata", ".data"]

    def test_extra_fields(self):
        log = parse_pe(self._row())
        assert log.extra["fuid"] == "FtestUID123"
        assert log.extra["machine"] == "AMD64"
        assert log.extra["is_64bit"] is True
        assert log.extra["has_cert_table"] is True

    def test_32bit_dll_message(self):
        log = parse_pe(self._row(is_exe=False, is_64bit=False))
        assert "DLL/OBJ" in log.message
        assert "32-bit" in log.message

    def test_tags(self):
        log = parse_pe(self._row())
        assert "zeek" in log.tags
        assert "pe" in log.tags

    def test_network_category(self):
        from shared.models import LogCategory
        log = parse_pe(self._row())
        assert log.event_category == LogCategory.NETWORK

    def test_no_ip_fields(self):
        """pe.log dosya UID ile çalışır, IP taşımaz — files.log'a göre çapraz sorgu gerekir."""
        log = parse_pe(self._row())
        assert log.source_ip is None
        assert log.destination_ip is None


class TestParseSmbMapping:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 445,
            "path": "\\\\10.0.0.5\\share",
            "service": "DISK",
            "native_file_system": "NTFS",
            "share_type": "DISK",
        }
        base.update(kw)
        return base

    def test_basic(self):
        log = parse_smb_mapping(self._row())
        assert log is not None
        assert log.event_action == "zeek_smb_share_mapped"
        assert log.source_ip == "192.168.1.100"
        assert log.destination_ip == "10.0.0.5"

    def test_no_path_returns_none(self):
        assert parse_smb_mapping(self._row(path="")) is None
        assert parse_smb_mapping(self._row(path="-")) is None

    def test_admin_share_c_dollar_flagged(self):
        log = parse_smb_mapping(self._row(path="\\\\10.0.0.5\\C$"))
        assert log.event_action == "zeek_smb_admin_share_mapped"
        assert log.severity == "warning"
        assert "lateral_movement" in log.tags
        assert "ADMIN_SHARE" in log.message

    def test_admin_share_admin_dollar_flagged(self):
        log = parse_smb_mapping(self._row(path="\\\\10.0.0.5\\ADMIN$"))
        assert log.event_action == "zeek_smb_admin_share_mapped"

    def test_ipc_share_flagged_in_message(self):
        log = parse_smb_mapping(self._row(path="\\\\10.0.0.5\\IPC$"))
        assert log.extra["is_ipc"] is True
        assert "IPC" in log.message

    def test_normal_share_not_flagged(self):
        log = parse_smb_mapping(self._row(path="\\\\10.0.0.5\\Public"))
        assert log.event_action == "zeek_smb_share_mapped"
        assert log.severity == "info"
        assert "lateral_movement" not in log.tags

    def test_extra_fields(self):
        log = parse_smb_mapping(self._row())
        assert log.extra["path"] == "\\\\10.0.0.5\\share"
        assert log.extra["service"] == "DISK"
        assert log.extra["share_type"] == "DISK"
        assert log.extra["native_file_system"] == "NTFS"

    def test_tags(self):
        log = parse_smb_mapping(self._row())
        assert "zeek" in log.tags
        assert "smb_mapping" in log.tags

    def test_network_category(self):
        from shared.models import LogCategory
        log = parse_smb_mapping(self._row())
        assert log.event_category == LogCategory.NETWORK

    def test_ports(self):
        log = parse_smb_mapping(self._row())
        assert log.source_port == 49152
        assert log.destination_port == 445


class TestParseSoftware:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "host": "192.168.1.50",
            "software_type": "HTTP::BROWSER",
            "name": "Chrome",
            "version.major": 120,
            "version.minor": 0,
            "version.minor2": 6099,
            "version.minor3": 109,
            "unparsed_version": "Chrome/120.0.6099.109",
        }
        base.update(kw)
        return base

    def test_basic(self):
        log = parse_software(self._row())
        assert log is not None
        assert log.event_action == "software_detected"
        assert log.source_ip == "192.168.1.50"
        assert "Chrome" in log.message
        assert "120.0.6099.109" in log.message

    def test_no_host_returns_none(self):
        assert parse_software(self._row(host="")) is None
        assert parse_software(self._row(host="-")) is None

    def test_no_name_returns_none(self):
        assert parse_software(self._row(name="")) is None
        assert parse_software(self._row(name="-")) is None

    def test_missing_software_type_defaults_unknown(self):
        log = parse_software(self._row(software_type="-"))
        assert log.extra["software_type"] == "UNKNOWN"

    def test_version_built_from_components(self):
        log = parse_software(self._row())
        assert log.extra["version"] == "120.0.6099.109"

    def test_version_falls_back_to_unparsed_when_no_components(self):
        log = parse_software(self._row(**{
            "version.major": "-", "version.minor": "-",
            "version.minor2": "-", "version.minor3": "-",
            "unparsed_version": "OpenSSH_8.9p1",
        }))
        assert log.extra["version"] == "OpenSSH_8.9p1"

    def test_partial_version_components(self):
        log = parse_software(self._row(**{
            "version.major": 8, "version.minor": 9,
            "version.minor2": "-", "version.minor3": "-",
        }))
        assert log.extra["version"] == "8.9"

    def test_addl_appended(self):
        log = parse_software(self._row(**{
            "version.major": 8, "version.minor": "-",
            "version.minor2": "-", "version.minor3": "-",
            "version.addl": "p1",
        }))
        assert log.extra["version"] == "8p1"

    def test_no_version_info_empty_string(self):
        log = parse_software(self._row(**{
            "version.major": "-", "version.minor": "-",
            "version.minor2": "-", "version.minor3": "-",
            "unparsed_version": "-",
        }))
        assert log.extra["version"] == ""

    def test_severity_always_info(self):
        log = parse_software(self._row())
        assert log.severity == "info"

    def test_tags(self):
        log = parse_software(self._row())
        assert "zeek" in log.tags
        assert "software" in log.tags

    def test_network_category(self):
        from shared.models import LogCategory
        log = parse_software(self._row())
        assert log.event_category == LogCategory.NETWORK

    def test_extra_fields(self):
        log = parse_software(self._row())
        assert log.extra["software_type"] == "HTTP::BROWSER"
        assert log.extra["name"] == "Chrome"


class TestParseNtp:
    def _row(self, **kw):
        base = {
            "ts": 1700000000.0,
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 123,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 123,
            "version": 4,
            "mode": 3,
            "stratum": 2,
            "ref_id": "GPS",
        }
        base.update(kw)
        return base

    def test_basic_client_query(self):
        log = parse_ntp(self._row())
        assert log is not None
        assert log.event_action == "ntp_activity"
        assert log.severity == "info"
        assert log.extra["mode"] == "client"

    def test_no_mode_returns_none(self):
        assert parse_ntp(self._row(mode="-")) is None
        assert parse_ntp(self._row(mode=None)) is None

    def test_control_mode_is_amplification_risk(self):
        log = parse_ntp(self._row(mode=6))
        assert log.severity == "warning"
        assert log.extra["is_amplification_risk"] is True
        assert "amplification_risk" in log.tags
        assert "AMPLIFICATION_RISK" in log.message

    def test_private_mode_is_amplification_risk(self):
        log = parse_ntp(self._row(mode=7))
        assert log.severity == "warning"
        assert log.extra["is_amplification_risk"] is True

    def test_normal_client_server_modes_not_flagged(self):
        for mode in (3, 4):
            log = parse_ntp(self._row(mode=mode))
            assert log.extra["is_amplification_risk"] is False
            assert log.severity == "info"

    def test_kiss_of_death_detected(self):
        log = parse_ntp(self._row(stratum=0, ref_id="RATE"))
        assert log.severity == "warning"
        assert log.extra["is_kiss_of_death"] is True
        assert "kiss_of_death" in log.tags
        assert "KISS_OF_DEATH" in log.message

    def test_stratum_zero_without_kiss_code_not_flagged(self):
        log = parse_ntp(self._row(stratum=0, ref_id="INIT"))
        assert log.extra["is_kiss_of_death"] is False
        assert log.severity == "info"

    def test_nonzero_stratum_with_kiss_string_not_flagged(self):
        """Kiss-of-death sadece stratum=0 ile birlikte anlamlıdır."""
        log = parse_ntp(self._row(stratum=2, ref_id="RATE"))
        assert log.extra["is_kiss_of_death"] is False

    def test_unknown_mode_labeled(self):
        log = parse_ntp(self._row(mode=0))
        assert log.extra["mode"] == "reserved"

    def test_ports(self):
        log = parse_ntp(self._row())
        assert log.source_port == 123
        assert log.destination_port == 123

    def test_udp_protocol(self):
        log = parse_ntp(self._row())
        assert log.network_protocol == "udp"

    def test_tags(self):
        log = parse_ntp(self._row())
        assert "zeek" in log.tags
        assert "ntp" in log.tags

    def test_network_category(self):
        from shared.models import LogCategory
        log = parse_ntp(self._row())
        assert log.event_category == LogCategory.NETWORK

    def test_missing_ref_id(self):
        log = parse_ntp(self._row(ref_id="-"))
        assert log.extra["ref_id"] == ""


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
        # Offset'i yapay olarak büyük yap (boyut < offset → rotation tespiti)
        key = str(log_file.resolve())
        zc._offsets[key] = {"offset": 99999, "inode": zc._offsets[key]["inode"]}

        zc.collect_once()
        assert len(saved) == 2  # tekrar okur

    def test_inode_change_triggers_reset_even_if_size_not_smaller(self, tmp_path, monkeypatch):
        """Dosya rotate olup yeni inode ile yeniden büyüdüğünde (boyut eski offset'i
        geçse bile) eski offset'ten değil baştan okunmalı — aksi halde yanlış noktadan
        okumaya devam eder ve satırlar bozuk/atlanmış olur."""
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        row1 = {"ts": 1700000000.0, "id.orig_h": "1.1.1.1", "id.resp_h": "8.8.8.8",
                "proto": "udp", "query": "first.com", "qtype_name": "A",
                "answers": [], "rcode_name": "NOERROR"}
        log_file = tmp_path / "dns.log"
        log_file.write_text(json.dumps(row1) + "\n")

        saved = []
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))
        zc.collect_once()
        assert len(saved) == 1

        # Rotation: yeni içerik ayrı dosyaya yazılıp rename ile taşınır —
        # tmpfs inode geri dönüşümüne karşı garantili farklı inode (logrotate gerçek davranışı)
        row2 = {"ts": 1700000100.0, "id.orig_h": "2.2.2.2", "id.resp_h": "8.8.8.8",
                "proto": "udp", "query": "second.com", "qtype_name": "A",
                "answers": [], "rcode_name": "NOERROR"}
        new_file = tmp_path / "_new_dns.log"
        new_file.write_text(json.dumps(row1) + "\n" + json.dumps(row2) + "\n")
        log_file.unlink()
        new_file.rename(log_file)

        zc.collect_once()
        # İnode değiştiği için offset sıfırlanıp dosya baştan okunmalı → 2 yeni satır
        assert len(saved) == 3
        assert "second.com" in saved[-1].message

    def test_save_failure_rolls_back_offset_for_retry(self, tmp_path, monkeypatch):
        """log_store.save() hata verirse offset o satırın öncesine geri alınmalı —
        aksi halde satır sessizce kaybolur (at-least-once garanti, Suricata ile tutarlı)."""
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        row = {"ts": 1700000000.0, "id.orig_h": "3.3.3.3", "id.resp_h": "8.8.8.8",
               "proto": "udp", "query": "retry.com", "qtype_name": "A",
               "answers": [], "rcode_name": "NOERROR"}
        log_file = tmp_path / "dns.log"
        log_file.write_text(json.dumps(row) + "\n")

        def _failing_save(log):
            raise RuntimeError("DB geçici olarak erişilemez")

        monkeypatch.setattr(zc.log_store, "save", _failing_save)
        n = zc.collect_once()
        assert n == 0

        key = str(log_file.resolve())
        assert zc._offsets[key]["offset"] == 0  # satır hiç işlenmemiş gibi kalmalı

        saved = []
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))
        n2 = zc.collect_once()
        assert n2 == 1
        assert saved[0].source_ip == "3.3.3.3"

    def test_offsets_persisted_atomically(self, tmp_path, monkeypatch):
        """Offset dosyası tempfile+os.replace ile yazılmalı — yarıda kesilmiş .tmp
        dosyası kalıcı offset dosyasını bozmamalı."""
        import server.zeek_collector as zc

        offset_file = tmp_path / "offsets.json"
        monkeypatch.setattr(zc, "ZEEK_OFFSET_FILE", offset_file)
        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        row = {"ts": 1700000000.0, "id.orig_h": "4.4.4.4", "id.resp_h": "8.8.8.8",
               "proto": "udp", "query": "atomic.com", "qtype_name": "A",
               "answers": [], "rcode_name": "NOERROR"}
        (tmp_path / "dns.log").write_text(json.dumps(row) + "\n")

        monkeypatch.setattr(zc.log_store, "save", lambda log: None)
        zc.collect_once()

        assert offset_file.exists()
        leftover_tmp = list(tmp_path.glob(".zeek_offsets_*.tmp"))
        assert leftover_tmp == []
        data = json.loads(offset_file.read_text())
        assert all("offset" in v and "inode" in v for v in data.values())


class TestRunZeekCollectorInotify:
    """B2 — run_zeek_collector() inotify ile poll aralığından çok daha hızlı tepki vermeli."""

    def test_reacts_to_new_file_faster_than_poll_interval(self, tmp_path, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        monkeypatch.setattr(zc, "POLL_INTERVAL", 30)  # poll devreye girerse test zaten timeout'tan önce kanıtlamış olur
        zc._offsets.clear()

        saved = []
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))

        async def scenario():
            task = asyncio.create_task(zc.run_zeek_collector())
            await asyncio.sleep(0.3)  # watcher'ın başlaması için

            row = {"ts": 1700000000.0, "id.orig_h": "5.5.5.5", "id.resp_h": "8.8.8.8",
                   "proto": "udp", "query": "inotify-test.com", "qtype_name": "A",
                   "answers": [], "rcode_name": "NOERROR"}
            (tmp_path / "dns.log").write_text(json.dumps(row) + "\n")

            for _ in range(60):  # en fazla ~3s bekle — 30s poll'a göre çok daha hızlı olmalı
                if saved:
                    break
                await asyncio.sleep(0.05)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(scenario())
        assert len(saved) == 1
        assert "inotify-test.com" in saved[0].message

    def test_falls_back_to_poll_when_directory_missing_at_start(self, tmp_path, monkeypatch):
        """Watcher dizini bulamazsa sessizce poll-only'e düşmeli, hata fırlatmamalı."""
        import server.zeek_collector as zc

        missing_dir = tmp_path / "not-yet-mounted"
        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", missing_dir)
        monkeypatch.setattr(zc, "POLL_INTERVAL", 0.2)
        zc._offsets.clear()

        async def scenario():
            task = asyncio.create_task(zc.run_zeek_collector())
            await asyncio.sleep(0.5)  # birkaç poll döngüsü geçsin, exception fırlamamalı
            assert not task.done()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(scenario())


class TestDhcpMacBaseline:
    """C1 — _check_dhcp_mac_baseline() ve collect_once() üzerinden entegrasyonu."""

    def test_first_sighting_no_alert(self, tmp_db):
        import server.zeek_collector as zc
        from shared.models import LogCategory, LogSourceType, NormalizedLog
        import datetime as dt

        log_entry = NormalizedLog(
            log_id="x", raw_id="y", source_type=LogSourceType.ZEEK,
            observer_hostname="zeek", timestamp=dt.datetime.now(dt.timezone.utc),
            severity="info", event_category=LogCategory.NETWORK, event_action="dhcp_lease",
            source_ip="192.168.1.50", message="test",
            extra={"mac": "aa:bb:cc:dd:ee:ff"},
        )
        result = zc._check_dhcp_mac_baseline(log_entry)
        assert result is None
        assert tmp_db.get_known_macs_for_ip("192.168.1.50") == ["aa:bb:cc:dd:ee:ff"]

    def test_same_mac_again_no_alert(self, tmp_db):
        import server.zeek_collector as zc
        from shared.models import LogCategory, LogSourceType, NormalizedLog
        import datetime as dt

        log_entry = NormalizedLog(
            log_id="x", raw_id="y", source_type=LogSourceType.ZEEK,
            observer_hostname="zeek", timestamp=dt.datetime.now(dt.timezone.utc),
            severity="info", event_category=LogCategory.NETWORK, event_action="dhcp_lease",
            source_ip="192.168.1.50", message="test",
            extra={"mac": "aa:bb:cc:dd:ee:ff"},
        )
        zc._check_dhcp_mac_baseline(log_entry)
        result = zc._check_dhcp_mac_baseline(log_entry)
        assert result is None

    def test_different_mac_triggers_alert(self, tmp_db):
        import server.zeek_collector as zc
        from shared.models import LogCategory, LogSourceType, NormalizedLog
        import datetime as dt

        first = NormalizedLog(
            log_id="x", raw_id="y", source_type=LogSourceType.ZEEK,
            observer_hostname="zeek", timestamp=dt.datetime.now(dt.timezone.utc),
            severity="info", event_category=LogCategory.NETWORK, event_action="dhcp_lease",
            source_ip="192.168.1.50", message="test",
            extra={"mac": "aa:bb:cc:dd:ee:ff"},
        )
        zc._check_dhcp_mac_baseline(first)

        second = first.model_copy(update={"extra": {"mac": "11:22:33:44:55:66"}})
        alert = zc._check_dhcp_mac_baseline(second)
        assert alert is not None
        assert alert.event_action == "dhcp_new_mac_detected"
        assert alert.severity == "warning"
        assert "11:22:33:44:55:66" in alert.message
        assert "aa:bb:cc:dd:ee:ff" in alert.message

    def test_missing_mac_no_crash(self, tmp_db):
        import server.zeek_collector as zc
        from shared.models import LogCategory, LogSourceType, NormalizedLog
        import datetime as dt

        log_entry = NormalizedLog(
            log_id="x", raw_id="y", source_type=LogSourceType.ZEEK,
            observer_hostname="zeek", timestamp=dt.datetime.now(dt.timezone.utc),
            severity="info", event_category=LogCategory.NETWORK, event_action="dhcp_lease",
            source_ip="192.168.1.50", message="test", extra={},
        )
        assert zc._check_dhcp_mac_baseline(log_entry) is None

    def test_collect_once_emits_new_mac_alert_end_to_end(self, tmp_path, tmp_db, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        saved = []
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))

        row1 = {"ts": 1700000000.0, "client_addr": "192.168.1.50", "server_addr": "192.168.1.1",
                "mac": "aa:bb:cc:dd:ee:ff", "assigned_addr": "192.168.1.50",
                "host_name": "host1", "lease_time": 3600.0, "msg_types": ["ACK"]}
        (tmp_path / "dhcp.log").write_text(json.dumps(row1) + "\n")
        zc.collect_once()
        assert len(saved) == 1  # sadece lease, ilk görülme

        # Aynı IP'ye farklı MAC ile yeni lease — rotation tetiklemeden yeni satır ekle
        row2 = {"ts": 1700000100.0, "client_addr": "192.168.1.50", "server_addr": "192.168.1.1",
                "mac": "11:22:33:44:55:66", "assigned_addr": "192.168.1.50",
                "host_name": "host2", "lease_time": 3600.0, "msg_types": ["ACK"]}
        with (tmp_path / "dhcp.log").open("a") as fh:
            fh.write(json.dumps(row2) + "\n")
        zc.collect_once()

        assert len(saved) == 3  # +1 lease +1 new_mac_detected
        actions = [s.event_action for s in saved]
        assert actions.count("dhcp_lease") == 2
        assert "dhcp_new_mac_detected" in actions


class TestDhcpStageMap:
    def test_new_mac_maps_to_recon(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("dhcp_new_mac_detected") == "recon"


class TestTunnelStageMap:
    def test_tunnel_detected_maps_to_lateral(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("network_tunnel_detected") == "lateral"


class TestTunnelCollectorWiring:
    def test_tunnel_log_processed_via_collect_once(self, tmp_path, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        row = {"ts": 1700000000.0, "id.orig_h": "10.0.0.9", "id.orig_p": 0,
               "id.resp_h": "203.0.113.5", "id.resp_p": 0,
               "tunnel_type": "Tunnel::GRE", "action": "Tunnel::DISCOVER"}
        (tmp_path / "tunnel.log").write_text(json.dumps(row) + "\n")

        saved = []
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))
        n = zc.collect_once()
        assert n == 1
        assert saved[0].event_action == "network_tunnel_detected"
        assert saved[0].severity == "warning"


class TestPeCollectorWiring:
    def test_pe_log_processed_via_collect_once(self, tmp_path, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        row = {"ts": 1700000000.0, "id": "FtestUID999", "machine": "AMD64",
               "os": "Windows", "subsystem": "WINDOWS_CUI",
               "is_exe": True, "is_64bit": True, "has_cert_table": False,
               "section_names": [".text", ".UPX0"]}
        (tmp_path / "pe.log").write_text(json.dumps(row) + "\n")

        saved = []
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))
        n = zc.collect_once()
        assert n == 1
        assert saved[0].event_action == "pe_metadata"
        assert saved[0].severity == "warning"


class TestSmbMappingStageMap:
    def test_admin_share_maps_to_lateral(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_smb_admin_share_mapped") == "lateral"

    def test_generic_share_maps_to_recon(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_smb_share_mapped") == "recon"


class TestSmbMappingCollectorWiring:
    def test_smb_mapping_log_processed_via_collect_once(self, tmp_path, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        row = {"ts": 1700000000.0, "id.orig_h": "192.168.1.100", "id.orig_p": 49152,
               "id.resp_h": "10.0.0.5", "id.resp_p": 445,
               "path": "\\\\10.0.0.5\\C$", "service": "DISK", "share_type": "DISK"}
        (tmp_path / "smb_mapping.log").write_text(json.dumps(row) + "\n")

        saved = []
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))
        n = zc.collect_once()
        assert n == 1
        assert saved[0].event_action == "zeek_smb_admin_share_mapped"
        assert saved[0].severity == "warning"


class TestSoftwareBaselineHook:
    def test_hook_adds_to_asset_baseline(self, tmp_db):
        import server.zeek_collector as zc
        from shared.models import LogCategory, LogSourceType, NormalizedLog
        import datetime as dt

        log_entry = NormalizedLog(
            log_id="x", raw_id="y", source_type=LogSourceType.ZEEK,
            observer_hostname="zeek", timestamp=dt.datetime.now(dt.timezone.utc),
            severity="info", event_category=LogCategory.NETWORK, event_action="software_detected",
            source_ip="192.168.1.50", message="test",
            extra={"software_type": "HTTP::BROWSER", "name": "Chrome", "version": "120.0"},
        )
        result = zc._attach_software_to_baseline(log_entry)
        assert result is None  # her zaman None — yeni alert üretmez
        software = tmp_db.get_detected_software("192.168.1.50")
        assert len(software) == 1
        assert software[0]["name"] == "Chrome"

    def test_hook_dedupes_same_software(self, tmp_db):
        import server.zeek_collector as zc
        from shared.models import LogCategory, LogSourceType, NormalizedLog
        import datetime as dt

        log_entry = NormalizedLog(
            log_id="x", raw_id="y", source_type=LogSourceType.ZEEK,
            observer_hostname="zeek", timestamp=dt.datetime.now(dt.timezone.utc),
            severity="info", event_category=LogCategory.NETWORK, event_action="software_detected",
            source_ip="192.168.1.50", message="test",
            extra={"software_type": "HTTP::BROWSER", "name": "Chrome", "version": "120.0"},
        )
        zc._attach_software_to_baseline(log_entry)
        zc._attach_software_to_baseline(log_entry)
        software = tmp_db.get_detected_software("192.168.1.50")
        assert len(software) == 1

    def test_hook_accumulates_different_software(self, tmp_db):
        import server.zeek_collector as zc
        from shared.models import LogCategory, LogSourceType, NormalizedLog
        import datetime as dt

        for name, ver in [("Chrome", "120.0"), ("OpenSSH", "8.9")]:
            log_entry = NormalizedLog(
                log_id="x", raw_id="y", source_type=LogSourceType.ZEEK,
                observer_hostname="zeek", timestamp=dt.datetime.now(dt.timezone.utc),
                severity="info", event_category=LogCategory.NETWORK, event_action="software_detected",
                source_ip="192.168.1.50", message="test",
                extra={"software_type": "X", "name": name, "version": ver},
            )
            zc._attach_software_to_baseline(log_entry)
        software = tmp_db.get_detected_software("192.168.1.50")
        assert len(software) == 2

    def test_hook_does_not_clobber_existing_baseline_fields(self, tmp_db):
        """Periyodik asset_baseline.py hesaplamasının diğer kolonlarını ezmemeli."""
        import server.zeek_collector as zc
        from shared.models import LogCategory, LogSourceType, NormalizedLog
        import datetime as dt

        tmp_db.upsert_asset_baseline(
            source_ip="192.168.1.50", tenant_id="default",
            first_seen_at=dt.datetime.now(dt.timezone.utc).isoformat(),
            last_seen_at=dt.datetime.now(dt.timezone.utc).isoformat(),
            avg_events_per_hour=42.0,
            typical_ports=[22, 443], typical_destinations=["8.8.8.8"],
            typical_event_actions=["ssh_success"], sample_hours=24,
            typical_protocols=["tcp"],
        )

        log_entry = NormalizedLog(
            log_id="x", raw_id="y", source_type=LogSourceType.ZEEK,
            observer_hostname="zeek", timestamp=dt.datetime.now(dt.timezone.utc),
            severity="info", event_category=LogCategory.NETWORK, event_action="software_detected",
            source_ip="192.168.1.50", message="test",
            extra={"software_type": "X", "name": "Chrome", "version": "120.0"},
        )
        zc._attach_software_to_baseline(log_entry)

        baseline = tmp_db.get_asset_baseline("192.168.1.50")
        assert baseline["avg_events_per_hour"] == 42.0
        assert baseline["typical_ports"] == [22, 443]
        assert len(baseline["detected_software"]) == 1

    def test_no_name_no_db_call(self, tmp_db):
        import server.zeek_collector as zc
        from shared.models import LogCategory, LogSourceType, NormalizedLog
        import datetime as dt

        log_entry = NormalizedLog(
            log_id="x", raw_id="y", source_type=LogSourceType.ZEEK,
            observer_hostname="zeek", timestamp=dt.datetime.now(dt.timezone.utc),
            severity="info", event_category=LogCategory.NETWORK, event_action="software_detected",
            source_ip="192.168.1.50", message="test", extra={},
        )
        assert zc._attach_software_to_baseline(log_entry) is None
        assert tmp_db.get_detected_software("192.168.1.50") == []


class TestSoftwareCollectorWiring:
    def test_software_log_processed_via_collect_once(self, tmp_path, tmp_db, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        row = {"ts": 1700000000.0, "host": "192.168.1.60", "software_type": "SSH::SERVER",
               "name": "OpenSSH", "version.major": 8, "version.minor": 9}
        (tmp_path / "software.log").write_text(json.dumps(row) + "\n")

        saved = []
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))
        n = zc.collect_once()
        assert n == 1
        assert saved[0].event_action == "software_detected"

        software = tmp_db.get_detected_software("192.168.1.60")
        assert len(software) == 1


class TestParseNoticeI5:
    """I5 — Zeek notice.log ek notice türleri ve STAGE_MAP bug fix."""

    def _row(self, note: str, src="192.168.1.10", dst="10.0.0.1"):
        return {
            "ts": 1700000000.0,
            "note": note,
            "msg": f"Notice: {note}",
            "src": src,
            "dst": dst,
            "proto": "tcp",
        }

    def test_address_scan_action(self):
        log = parse_notice(self._row("Scan::Address_Scan"))
        assert log is not None
        assert log.event_action == "zeek_scan_address_scan"

    def test_ssh_password_guessing_action(self):
        log = parse_notice(self._row("SSH::Password_Guessing"))
        assert log is not None
        assert log.event_action == "zeek_ssh_password_guessing"

    def test_http_sql_injection_action(self):
        log = parse_notice(self._row("HTTP::SQL_Injection_Attacker"))
        assert log is not None
        assert log.event_action == "zeek_http_sql_injection_attacker"

    def test_ssl_self_signed_cert_action(self):
        log = parse_notice(self._row("SSL::Self_Signed_Cert"))
        assert log is not None
        assert log.event_action == "zeek_ssl_self_signed_cert"

    def test_stage_map_port_scan(self):
        from server.attack_chain import STAGE_MAP
        assert "zeek_scan_port_scan" in STAGE_MAP
        assert STAGE_MAP["zeek_scan_port_scan"] == "recon"
        assert "zeek_port" not in STAGE_MAP, "Eski yanlış key kaldırılmadı"

    def test_stage_map_address_scan(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_scan_address_scan") == "recon"

    def test_stage_map_ssh_password_guessing(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_ssh_password_guessing") == "weaponize"

    def test_stage_map_sql_injection(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_http_sql_injection_attacker") == "weaponize"

    def test_stage_map_self_signed_cert(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_ssl_self_signed_cert") == "lateral"

    def test_unknown_notice_still_parses(self):
        log = parse_notice(self._row("Custom::Some_Notice"))
        assert log is not None
        assert log.event_action == "zeek_custom_some_notice"


class TestNtpCollectorWiring:
    def test_ntp_log_processed_via_collect_once(self, tmp_path, monkeypatch):
        import server.zeek_collector as zc

        monkeypatch.setattr(zc, "ZEEK_LOG_DIR", tmp_path)
        zc._offsets.clear()

        row = {"ts": 1700000000.0, "id.orig_h": "203.0.113.7", "id.orig_p": 123,
               "id.resp_h": "192.168.1.1", "id.resp_p": 123, "mode": 7, "stratum": 1}
        (tmp_path / "ntp.log").write_text(json.dumps(row) + "\n")

        saved = []
        monkeypatch.setattr(zc.log_store, "save", lambda log: saved.append(log))
        n = zc.collect_once()
        assert n == 1
        assert saved[0].event_action == "ntp_activity"
        assert saved[0].severity == "warning"


# ─────────────────────────────────────────────────────────────────────────────
#  I6 — Legacy TLS / SSL Strip (Zeek ssl.log)
# ─────────────────────────────────────────────────────────────────────────────

class TestParseSSLI6:
    _TS = 1718000000.0

    def _base_row(self) -> dict:
        return {
            "ts": self._TS,
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "203.0.113.5",
            "id.resp_p": "443",
            "server_name": "example.com",
            "validation_status": "",
            "subject": "",
            "ja4": "",
            "ja4s": "",
            "ja3": "",
            "ja3s": "",
            "version": "TLSv13",
            "established": "T",
        }

    def test_legacy_tls10_detected(self):
        from server.parsers.zeek import parse_ssl
        row = self._base_row()
        row["version"] = "TLSv10"
        log = parse_ssl(row)
        assert log is not None
        assert log.event_action == "ssl_old_version_detected"
        assert log.severity == "warning"
        assert "TLSv10" in log.message

    def test_legacy_sslv3_detected(self):
        from server.parsers.zeek import parse_ssl
        row = self._base_row()
        row["version"] = "SSLv3"
        log = parse_ssl(row)
        assert log is not None
        assert log.event_action == "ssl_old_version_detected"
        assert "SSLv3" in log.message

    def test_modern_tls_not_flagged_as_legacy(self):
        from server.parsers.zeek import parse_ssl
        row = self._base_row()
        row["version"] = "TLSv13"
        log = parse_ssl(row)
        assert log is not None
        assert log.event_action != "ssl_old_version_detected"

    def test_ssl_strip_established_false_port_443(self):
        from server.parsers.zeek import parse_ssl
        row = self._base_row()
        row["version"] = ""
        row["established"] = "F"
        log = parse_ssl(row)
        assert log is not None
        assert log.event_action == "ssl_strip_possible"
        assert log.severity == "warning"
        assert log.destination_port == 443

    def test_ssl_strip_not_flagged_other_port(self):
        from server.parsers.zeek import parse_ssl
        row = self._base_row()
        row["id.resp_p"] = "8443"
        row["established"] = "F"
        log = parse_ssl(row)
        assert log is not None
        assert log.event_action != "ssl_strip_possible"

    def test_stage_map_old_version(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("ssl_old_version_detected") == "lateral"

    def test_stage_map_ssl_strip(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("ssl_strip_possible") == "lateral"
