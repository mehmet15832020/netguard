"""Suricata EVE JSON collector ve parser testleri."""

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from server.parsers.suricata import (
    parse_alert, parse_dns, parse_http, parse_tls,
    parse_flow, parse_smtp, parse_fileinfo, parse_ssh,
    parse_anomaly, parse_eve_line,
    _SUSPICIOUS_UA_PATTERNS, _OLD_TLS_VERSIONS, _SUSPICIOUS_SSH_CLIENTS,
    _is_suspicious_ua, _is_old_tls_version, _is_suspicious_ssh_client,
)
from server.parsers.zeek import _KNOWN_BAD_JA3, _KNOWN_BAD_JA4
from shared.models import LogCategory, LogSourceType


# ── Yardımcı ──────────────────────────────────────────────────────────────────

_TS = "2024-01-15T12:00:00.000000+0000"
_SRC = "192.168.1.50"
_DST = "203.0.113.10"


def _base(**kw):
    row = {
        "timestamp": _TS,
        "src_ip":    _SRC,
        "src_port":  12345,
        "dest_ip":   _DST,
        "dest_port": 443,
        "proto":     "TCP",
    }
    row.update(kw)
    return row


# ─────────────────────────────────────────────────────────────────────────────
#  1. parse_alert
# ─────────────────────────────────────────────────────────────────────────────

class TestParseAlert:
    def _row(self, **kw):
        alert = {
            "signature_id": 2100498,
            "signature":    "GPL ATTACK_RESPONSE id check returned root",
            "category":     "Potentially Bad Traffic",
            "severity":     2,
            "action":       "allowed",
        }
        alert.update(kw)
        return _base(event_type="alert", alert=alert)

    def test_basic_fields(self):
        log = parse_alert(self._row())
        assert log is not None
        assert log.event_action == "suricata_alert"
        assert log.source_type == LogSourceType.SURICATA
        assert log.event_category == LogCategory.INTRUSION
        assert log.source_ip == _SRC
        assert log.destination_ip == _DST
        assert "2100498" in log.message

    def test_severity_priority_1_is_critical(self):
        log = parse_alert(self._row(severity=1))
        assert log.severity == "critical"

    def test_severity_priority_2_is_warning(self):
        log = parse_alert(self._row(severity=2))
        assert log.severity == "warning"

    def test_severity_priority_3_is_info(self):
        log = parse_alert(self._row(severity=3))
        assert log.severity == "info"

    def test_category_in_tags(self):
        log = parse_alert(self._row())
        assert any("potentially" in t for t in log.tags)

    def test_blocked_action_in_tags(self):
        log = parse_alert(self._row(action="blocked"))
        assert "blocked" in log.tags

    def test_empty_alert_returns_none(self):
        row = _base(event_type="alert", alert={})
        assert parse_alert(row) is None

    def test_missing_alert_returns_none(self):
        assert parse_alert(_base(event_type="alert")) is None

    def test_extra_contains_sid(self):
        log = parse_alert(self._row())
        assert log.extra["sid"] == "2100498"

    def test_tags_contain_ids_alert(self):
        log = parse_alert(self._row())
        assert "ids_alert" in log.tags
        assert "suricata" in log.tags


# ─────────────────────────────────────────────────────────────────────────────
#  2. parse_dns
# ─────────────────────────────────────────────────────────────────────────────

class TestParseDnsSuricata:
    def _row(self, **kw):
        dns = {"type": "query", "rrname": "example.com", "rrtype": "A", "rcode": "NOERROR"}
        dns.update(kw)
        return _base(event_type="dns", proto="UDP", src_port=54321, dest_port=53, dns=dns)

    def test_basic(self):
        log = parse_dns(self._row())
        assert log is not None
        assert log.event_action == "dns_query"
        assert "example.com" in log.message

    def test_nxdomain_in_message(self):
        log = parse_dns(self._row(rcode="NXDOMAIN"))
        assert "NXDOMAIN" in log.message

    def test_empty_dns_returns_none(self):
        assert parse_dns(_base(event_type="dns", dns={})) is None

    def test_missing_dns_returns_none(self):
        assert parse_dns(_base(event_type="dns")) is None

    def test_source_type_is_suricata(self):
        log = parse_dns(self._row())
        assert log.source_type == LogSourceType.SURICATA


# ─────────────────────────────────────────────────────────────────────────────
#  3. parse_http
# ─────────────────────────────────────────────────────────────────────────────

class TestParseHttp:
    def _row(self, **kw):
        http = {
            "hostname":       "evil.example.com",
            "url":            "/upload/payload",
            "http_method":    "POST",
            "status":         200,
            "length":         1024,
            "http_user_agent": "python-requests/2.28",
        }
        http.update(kw)
        return _base(event_type="http", http=http)

    def test_basic_fields(self):
        log = parse_http(self._row())
        assert log is not None
        assert log.event_action == "http_request"
        assert "evil.example.com" in log.message
        assert "POST" in log.message

    def test_4xx_status_is_warning(self):
        log = parse_http(self._row(status=403))
        assert log.severity == "warning"

    def test_200_status_is_info(self):
        log = parse_http(self._row(status=200))
        assert log.severity == "info"

    def test_empty_http_returns_none(self):
        assert parse_http(_base(event_type="http", http={})) is None

    def test_user_agent_in_message(self):
        log = parse_http(self._row())
        assert "python-requests" in log.message


# ─────────────────────────────────────────────────────────────────────────────
#  4. parse_tls
# ─────────────────────────────────────────────────────────────────────────────

class TestParseTls:
    def _row(self, **kw):
        tls = {
            "sni":        "github.com",
            "version":    "TLSv1.3",
            "subject":    "CN=github.com",
            "issuerdn":   "CN=DigiCert",
            "ja3":        {"hash": "abcdef1234567890abcdef1234567890"},
        }
        tls.update(kw)
        return _base(event_type="tls", tls=tls)

    def test_normal_tls_is_ssl_connection(self):
        log = parse_tls(self._row())
        assert log is not None
        assert log.event_action == "ssl_connection"
        assert log.severity == "info"

    def test_bad_ja3_triggers_suspicious(self):
        bad = next(iter(_KNOWN_BAD_JA3))
        log = parse_tls(self._row(ja3={"hash": bad}))
        assert log is not None
        assert log.event_action == "tls_suspicious_fingerprint"
        assert log.severity == "warning"   # JA4 primary: JA3-only → warning
        assert "KNOWN_MALWARE_JA3" in log.message

    def test_bad_ja4_triggers_suspicious(self):
        bad = next(iter(_KNOWN_BAD_JA4))
        row = self._row()
        row["tls"]["ja4"] = bad
        log = parse_tls(row)
        assert log is not None
        assert log.event_action == "tls_suspicious_fingerprint"
        assert "KNOWN_MALWARE_JA4" in log.message

    def test_self_signed_in_message(self):
        log = parse_tls(self._row(issuerdn="CN=evil.local", subject="CN=evil.local"))
        assert log is not None
        assert "SELF-SIGNED" in log.message

    def test_empty_tls_returns_none(self):
        assert parse_tls(_base(event_type="tls", tls={})) is None

    def test_missing_tls_returns_none(self):
        assert parse_tls(_base(event_type="tls")) is None

    def test_sni_in_message(self):
        log = parse_tls(self._row())
        assert "github.com" in log.message

    def test_ja3_hash_in_message_when_present(self):
        log = parse_tls(self._row())
        assert "JA3=" in log.message

    def test_flat_ja3_hash_form_detected(self):
        """Suricata ≥7 varsayılan EVE çıktısı: tls.ja3_hash düz string."""
        bad = next(iter(_KNOWN_BAD_JA3))
        row = self._row()
        # Flat form: tls.ja3_hash (nested dict yok)
        row["tls"].pop("ja3", None)
        row["tls"]["ja3_hash"] = bad
        log = parse_tls(row)
        assert log is not None
        assert log.event_action == "tls_suspicious_fingerprint"
        assert "KNOWN_MALWARE_JA3" in log.message

    def test_bad_ja4_is_critical_bad_ja3_is_warning(self):
        """JA4 primary politikası: JA4 kötü → critical, yalnız JA3 kötü → warning."""
        bad_ja4 = next(iter(_KNOWN_BAD_JA4))
        bad_ja3 = next(iter(_KNOWN_BAD_JA3))
        row_ja4 = self._row()
        row_ja4["tls"]["ja4"] = bad_ja4
        log_ja4 = parse_tls(row_ja4)
        assert log_ja4.severity == "critical"

        row_ja3 = self._row(ja3={"hash": bad_ja3})
        log_ja3 = parse_tls(row_ja3)
        assert log_ja3.severity == "warning"


# ─────────────────────────────────────────────────────────────────────────────
#  5. parse_flow
# ─────────────────────────────────────────────────────────────────────────────

class TestParseFlow:
    def _row(self, **kw):
        flow = {
            "pkts_toserver":  10,
            "pkts_toclient":  5,
            "bytes_toserver": 1500,
            "bytes_toclient": 8000,
            "state":          "closed",
            "reason":         "timeout",
        }
        flow.update(kw)
        return _base(event_type="flow", flow=flow)

    def test_basic(self):
        log = parse_flow(self._row())
        assert log is not None
        assert log.event_action == "network_flow"
        assert log.severity == "info"

    def test_bytes_in_extra(self):
        log = parse_flow(self._row())
        assert log.extra["bytes_toserver"] == 1500
        assert log.extra["bytes_toclient"] == 8000

    def test_empty_flow_returns_none(self):
        assert parse_flow(_base(event_type="flow", flow={})) is None


# ─────────────────────────────────────────────────────────────────────────────
#  6. parse_smtp
# ─────────────────────────────────────────────────────────────────────────────

class TestParseSmtp:
    def _row(self, **kw):
        smtp = {
            "helo":      "mail.example.com",
            "mail_from": "<sender@example.com>",
            "rcpt_to":   ["<victim@target.com>"],
        }
        smtp.update(kw)
        return _base(event_type="smtp", dest_port=25, smtp=smtp)

    def test_basic(self):
        log = parse_smtp(self._row())
        assert log is not None
        assert log.event_action == "smtp_session"
        assert "sender@example.com" in log.message

    def test_rcpt_in_message(self):
        log = parse_smtp(self._row())
        assert "victim@target.com" in log.message

    def test_empty_smtp_returns_none(self):
        assert parse_smtp(_base(event_type="smtp", smtp={})) is None


# ─────────────────────────────────────────────────────────────────────────────
#  7. parse_fileinfo
# ─────────────────────────────────────────────────────────────────────────────

class TestParseFileinfo:
    def _row(self, **kw):
        fi = {
            "filename": "/malware.exe",
            "magic":    "PE32 executable",
            "md5":      "d41d8cd98f00b204e9800998ecf8427e",
            "size":     204800,
            "state":    "CLOSED",
        }
        fi.update(kw)
        return _base(event_type="fileinfo", fileinfo=fi)

    def test_basic(self):
        log = parse_fileinfo(self._row())
        assert log is not None
        assert log.event_action == "file_download"
        assert "malware.exe" in log.message
        assert "PE32" in log.message

    def test_truncated_state_is_warning(self):
        log = parse_fileinfo(self._row(state="TRUNCATED"))
        assert log.severity == "warning"

    def test_normal_state_is_info(self):
        log = parse_fileinfo(self._row(state="CLOSED"))
        assert log.severity == "info"

    def test_md5_in_message(self):
        log = parse_fileinfo(self._row())
        assert "d41d8cd98f00b204" in log.message

    def test_empty_fileinfo_returns_none(self):
        assert parse_fileinfo(_base(event_type="fileinfo", fileinfo={})) is None


# ─────────────────────────────────────────────────────────────────────────────
#  8. parse_ssh
# ─────────────────────────────────────────────────────────────────────────────

class TestParseSsh:
    def _row(self, **kw):
        ssh = {
            "client": {"software_version": "OpenSSH_8.4", "proto_version": "2.0"},
            "server": {"software_version": "OpenSSH_9.0"},
        }
        ssh.update(kw)
        return _base(event_type="ssh", dest_port=22, ssh=ssh)

    def test_basic(self):
        log = parse_ssh(self._row())
        assert log is not None
        assert log.event_action == "ssh_attempt"
        assert "OpenSSH_8.4" in log.message

    def test_empty_ssh_returns_none(self):
        assert parse_ssh(_base(event_type="ssh", ssh={})) is None

    def test_category_is_authentication(self):
        log = parse_ssh(self._row())
        assert log.event_category == LogCategory.AUTHENTICATION


# ─────────────────────────────────────────────────────────────────────────────
#  9. parse_anomaly
# ─────────────────────────────────────────────────────────────────────────────

class TestParseAnomaly:
    def _row(self, **kw):
        anomaly = {"type": "stream", "event": "stream_gap", "layer": "transport"}
        anomaly.update(kw)
        return _base(event_type="anomaly", anomaly=anomaly)

    def test_basic(self):
        log = parse_anomaly(self._row())
        assert log is not None
        assert log.event_action == "suricata_anomaly"
        assert log.severity == "warning"
        assert "stream_gap" in log.message

    def test_empty_anomaly_returns_none(self):
        assert parse_anomaly(_base(event_type="anomaly", anomaly={})) is None


# ─────────────────────────────────────────────────────────────────────────────
#  10. parse_eve_line dispatcher
# ─────────────────────────────────────────────────────────────────────────────

class TestParseEveLine:
    def test_dispatches_alert(self):
        row = _base(
            event_type="alert",
            alert={"signature_id": 1, "signature": "Test", "category": "", "severity": 2, "action": "allowed"},
        )
        log = parse_eve_line(row)
        assert log is not None
        assert log.event_action == "suricata_alert"

    def test_dispatches_dns(self):
        row = _base(
            event_type="dns",
            proto="UDP",
            src_port=54321,
            dest_port=53,
            dns={"type": "query", "rrname": "test.com", "rrtype": "A", "rcode": "NOERROR"},
        )
        log = parse_eve_line(row)
        assert log is not None
        assert log.event_action == "dns_query"

    def test_unknown_event_type_returns_none(self):
        assert parse_eve_line(_base(event_type="unknown_type")) is None

    def test_missing_event_type_returns_none(self):
        assert parse_eve_line(_base()) is None

    def test_parser_exception_returns_none(self):
        # Bozuk tls alanı — exception yerine None dönmeli
        row = _base(event_type="tls", tls={"ja3": "not_a_dict"})
        result = parse_eve_line(row)
        # tls dict değil string olsa da parse_tls None döner (no sni/version)
        # En önemlisi exception fırlatmamalı
        assert result is None or result.event_action in ("ssl_connection", "tls_suspicious_fingerprint")


# ─────────────────────────────────────────────────────────────────────────────
#  11. collect_once — dosya okuma ve offset takibi
# ─────────────────────────────────────────────────────────────────────────────

class TestCollectOnce:
    def _write_eve(self, tmp_path: Path, events: list[dict]) -> Path:
        eve = tmp_path / "eve.json"
        eve.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
        return eve

    def _alert_event(self):
        return {
            "timestamp": _TS,
            "event_type": "alert",
            "src_ip": _SRC, "src_port": 12345,
            "dest_ip": _DST, "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature_id": 1, "signature": "Test alert",
                "category": "Test", "severity": 2, "action": "allowed",
            },
        }

    def test_collect_once_processes_alert(self, tmp_path):
        eve_path = self._write_eve(tmp_path, [self._alert_event()])
        saved = []

        import server.suricata_collector as sc
        original_eve = sc.SURICATA_EVE_LOG
        original_offset = sc._offset

        try:
            sc.SURICATA_EVE_LOG = eve_path
            sc._offset = 0

            with patch("server.suricata_collector.log_store") as mock_store, \
                 patch("server.suricata_collector._save_offset"):
                mock_store.save.side_effect = saved.append
                count = sc.collect_once()

            assert count == 1
            assert len(saved) == 1
            assert saved[0].event_action == "suricata_alert"
        finally:
            sc.SURICATA_EVE_LOG = original_eve
            sc._offset = original_offset

    def test_collect_once_nonexistent_file_returns_zero(self, tmp_path):
        import server.suricata_collector as sc
        original_eve = sc.SURICATA_EVE_LOG
        try:
            sc.SURICATA_EVE_LOG = tmp_path / "nonexistent.json"
            assert sc.collect_once() == 0
        finally:
            sc.SURICATA_EVE_LOG = original_eve

    def test_collect_once_skips_unknown_event_type(self, tmp_path):
        events = [
            {"timestamp": _TS, "event_type": "stats", "src_ip": _SRC,
             "src_port": 1, "dest_ip": _DST, "dest_port": 2, "proto": "TCP"},
        ]
        eve_path = self._write_eve(tmp_path, events)

        import server.suricata_collector as sc
        original_eve = sc.SURICATA_EVE_LOG
        original_offset = sc._offset

        try:
            sc.SURICATA_EVE_LOG = eve_path
            sc._offset = 0
            with patch("server.suricata_collector.log_store"), \
                 patch("server.suricata_collector._save_offset"):
                count = sc.collect_once()
            assert count == 0
        finally:
            sc.SURICATA_EVE_LOG = original_eve
            sc._offset = original_offset

    def test_offset_advances_after_read(self, tmp_path):
        eve_path = self._write_eve(tmp_path, [self._alert_event()])

        import server.suricata_collector as sc
        original_eve = sc.SURICATA_EVE_LOG
        original_offset = sc._offset

        try:
            sc.SURICATA_EVE_LOG = eve_path
            sc._offset = 0

            with patch("server.suricata_collector.log_store"), \
                 patch("server.suricata_collector._save_offset"):
                sc.collect_once()
                offset_after_first = sc._offset

            with patch("server.suricata_collector.log_store") as mock_store, \
                 patch("server.suricata_collector._save_offset"):
                count = sc.collect_once()

            # Offset ilerledikten sonra aynı satır tekrar işlenmemeli
            assert count == 0
            assert sc._offset == offset_after_first
        finally:
            sc.SURICATA_EVE_LOG = original_eve
            sc._offset = original_offset

    def test_inode_change_resets_offset(self, tmp_path):
        """Log rotation: farklı inode → offset sıfırlanır."""
        eve_path = self._write_eve(tmp_path, [self._alert_event()])
        saved = []

        import server.suricata_collector as sc
        original_eve = sc.SURICATA_EVE_LOG
        original_offset = sc._offset
        original_inode  = sc._inode

        try:
            sc.SURICATA_EVE_LOG = eve_path
            sc._offset = 999999   # simüle edilmiş eski offset
            sc._inode  = 0        # farklı inode → rotation tetiklenir

            with patch("server.suricata_collector.log_store") as mock_store, \
                 patch("server.suricata_collector._save_offset"):
                mock_store.save.side_effect = saved.append
                count = sc.collect_once()

            assert count == 1
            assert len(saved) == 1
        finally:
            sc.SURICATA_EVE_LOG = original_eve
            sc._offset = original_offset
            sc._inode  = original_inode

    def test_malformed_json_skipped(self, tmp_path):
        eve = tmp_path / "eve.json"
        eve.write_text('{"event_type": "alert", MALFORMED}\n{"timestamp":"x","event_type":"stats"}\n',
                       encoding="utf-8")

        import server.suricata_collector as sc
        original_eve = sc.SURICATA_EVE_LOG
        original_offset = sc._offset

        try:
            sc.SURICATA_EVE_LOG = eve
            sc._offset = 0
            with patch("server.suricata_collector.log_store"), \
                 patch("server.suricata_collector._save_offset"):
                count = sc.collect_once()
            assert count == 0
        finally:
            sc.SURICATA_EVE_LOG = original_eve
            sc._offset = original_offset

    def test_multiple_events_all_processed(self, tmp_path):
        events = [self._alert_event() for _ in range(5)]
        eve_path = self._write_eve(tmp_path, events)
        saved = []

        import server.suricata_collector as sc
        original_eve = sc.SURICATA_EVE_LOG
        original_offset = sc._offset

        try:
            sc.SURICATA_EVE_LOG = eve_path
            sc._offset = 0
            with patch("server.suricata_collector.log_store") as mock_store, \
                 patch("server.suricata_collector._save_offset"):
                mock_store.save.side_effect = saved.append
                count = sc.collect_once()
            assert count == 5
            assert len(saved) == 5
        finally:
            sc.SURICATA_EVE_LOG = original_eve
            sc._offset = original_offset


# ─────────────────────────────────────────────────────────────────────────────
#  12. cleanup_old_logs
# ─────────────────────────────────────────────────────────────────────────────

class TestCleanupOldLogs:
    def test_deletes_old_rotation_file(self, tmp_path):
        import time
        import server.suricata_collector as sc
        original_eve = sc.SURICATA_EVE_LOG

        try:
            eve_path = tmp_path / "eve.json"
            eve_path.touch()
            sc.SURICATA_EVE_LOG = eve_path

            old_file = tmp_path / "eve.2024-01-01.json"
            old_file.touch()
            # Dosyanın mtime'ını çok eski yap
            old_time = time.time() - (sc._LOG_RETENTION_DAYS + 1) * 86400
            import os
            os.utime(old_file, (old_time, old_time))

            deleted = sc.cleanup_old_logs()
            assert deleted >= 1
            assert not old_file.exists()
        finally:
            sc.SURICATA_EVE_LOG = original_eve

    def test_preserves_recent_files(self, tmp_path):
        import server.suricata_collector as sc
        original_eve = sc.SURICATA_EVE_LOG

        try:
            eve_path = tmp_path / "eve.json"
            eve_path.touch()
            sc.SURICATA_EVE_LOG = eve_path

            recent = tmp_path / "eve.2099-01-01.json"
            recent.touch()

            deleted = sc.cleanup_old_logs()
            assert deleted == 0
            assert recent.exists()
        finally:
            sc.SURICATA_EVE_LOG = original_eve


# ─────────────────────────────────────────────────────────────────────────────
#  G7 — HTTP / TLS / SSH anomaly detection
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpAnomalyDetection:
    def _row(self, ua="Mozilla/5.0 Firefox/120.0", status=200, **kw):
        http = {
            "hostname":        "example.com",
            "url":             "/index.html",
            "http_method":     "GET",
            "status":          status,
            "length":          512,
            "http_user_agent": ua,
        }
        http.update(kw)
        return _base(event_type="http", http=http)

    def test_normal_ua_is_http_request(self):
        log = parse_http(self._row())
        assert log.event_action == "http_request"

    def test_empty_ua_is_anomaly(self):
        log = parse_http(self._row(ua=""))
        assert log.event_action == "suricata_http_anomaly"
        assert log.severity == "warning"
        assert "SUSPICIOUS-UA" in log.message

    def test_whitespace_only_ua_is_anomaly(self):
        log = parse_http(self._row(ua="   "))
        assert log.event_action == "suricata_http_anomaly"

    def test_sqlmap_ua_is_anomaly(self):
        log = parse_http(self._row(ua="sqlmap/1.7.11"))
        assert log.event_action == "suricata_http_anomaly"
        assert "suspicious_ua" in log.tags

    def test_nikto_ua_is_anomaly(self):
        log = parse_http(self._row(ua="Mozilla/5.0 (nikto scanner)"))
        assert log.event_action == "suricata_http_anomaly"

    def test_nuclei_ua_is_anomaly(self):
        log = parse_http(self._row(ua="Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"))
        assert log.event_action == "suricata_http_anomaly"

    def test_ffuf_ua_is_anomaly(self):
        log = parse_http(self._row(ua="Fuzz Faster U Fool v1.5.0-dev ffuf"))
        assert log.event_action == "suricata_http_anomaly"

    def test_python_requests_is_not_anomaly(self):
        log = parse_http(self._row(ua="python-requests/2.31.0"))
        assert log.event_action == "http_request"

    def test_curl_is_not_anomaly(self):
        log = parse_http(self._row(ua="curl/7.88.1"))
        assert log.event_action == "http_request"

    def test_anomaly_ua_stored_in_extra(self):
        log = parse_http(self._row(ua="sqlmap/1.7"))
        assert log.extra["user_agent"] == "sqlmap/1.7"

    def test_is_suspicious_ua_helper(self):
        assert _is_suspicious_ua("") is True
        assert _is_suspicious_ua("sqlmap/1.7") is True
        assert _is_suspicious_ua("Mozilla/5.0") is False
        assert _is_suspicious_ua("python-requests/2.31") is False


class TestTlsAnomalyDetection:
    def _row(self, version="TLSv1.3", issuerdn="CN=DigiCert", subject="CN=example.com", **kw):
        tls = {
            "sni":      "example.com",
            "version":  version,
            "subject":  subject,
            "issuerdn": issuerdn,
            "ja3":      {"hash": "abcdef1234567890abcdef1234567890"},
        }
        tls.update(kw)
        return _base(event_type="tls", tls=tls)

    def test_normal_tls_unchanged(self):
        log = parse_tls(self._row())
        assert log.event_action == "ssl_connection"
        assert log.severity == "info"

    def test_self_signed_is_tls_anomaly(self):
        log = parse_tls(self._row(issuerdn="CN=evil.c2", subject="CN=evil.c2"))
        assert log.event_action == "suricata_tls_anomaly"
        assert log.severity == "warning"
        assert "SELF-SIGNED" in log.message

    def test_old_tls10_is_anomaly(self):
        log = parse_tls(self._row(version="TLSv1"))
        assert log.event_action == "suricata_tls_anomaly"
        assert "OLD-TLS-VERSION" in log.message
        assert log.severity == "warning"

    def test_old_tls11_is_anomaly(self):
        log = parse_tls(self._row(version="TLSv1.1"))
        assert log.event_action == "suricata_tls_anomaly"

    def test_sslv3_is_anomaly(self):
        log = parse_tls(self._row(version="SSLv3"))
        assert log.event_action == "suricata_tls_anomaly"

    def test_bad_ja4_takes_priority_over_old_version(self):
        bad = next(iter(_KNOWN_BAD_JA4))
        row = self._row(version="TLSv1")
        row["tls"]["ja4"] = bad
        log = parse_tls(row)
        assert log.event_action == "tls_suspicious_fingerprint"

    def test_tls_anomaly_tag_added(self):
        log = parse_tls(self._row(version="TLSv1.1"))
        assert "tls_anomaly" in log.tags

    def test_is_old_tls_version_helper(self):
        assert _is_old_tls_version("TLSv1") is True
        assert _is_old_tls_version("TLSv1.1") is True
        assert _is_old_tls_version("SSLv3") is True
        assert _is_old_tls_version("TLSv1.3") is False
        assert _is_old_tls_version("TLSv1.2") is False
        assert _is_old_tls_version("") is False


class TestSshAnomalyDetection:
    def _row(self, client_sw="OpenSSH_8.9", **kw):
        ssh = {
            "client": {"software_version": client_sw, "proto_version": "2.0"},
            "server": {"software_version": "OpenSSH_9.0"},
        }
        ssh.update(kw)
        return _base(event_type="ssh", dest_port=22, ssh=ssh)

    def test_normal_client_unchanged(self):
        log = parse_ssh(self._row())
        assert log.event_action == "ssh_attempt"
        assert log.severity == "info"

    def test_paramiko_is_anomaly(self):
        log = parse_ssh(self._row(client_sw="paramiko_3.1.0"))
        assert log.event_action == "suricata_ssh_anomaly"
        assert log.severity == "warning"
        assert "SUSPICIOUS-CLIENT" in log.message

    def test_libssh_is_anomaly(self):
        log = parse_ssh(self._row(client_sw="libssh-0.9.6"))
        assert log.event_action == "suricata_ssh_anomaly"

    def test_nmap_is_anomaly(self):
        log = parse_ssh(self._row(client_sw="nmap ssh scanner"))
        assert log.event_action == "suricata_ssh_anomaly"

    def test_masscan_is_anomaly(self):
        log = parse_ssh(self._row(client_sw="masscan"))
        assert log.event_action == "suricata_ssh_anomaly"
        assert "suspicious_client" in log.tags

    def test_putty_is_not_anomaly(self):
        log = parse_ssh(self._row(client_sw="PuTTY_Release_0.79"))
        assert log.event_action == "ssh_attempt"

    def test_is_suspicious_ssh_client_helper(self):
        assert _is_suspicious_ssh_client("paramiko_3.1") is True
        assert _is_suspicious_ssh_client("libssh-0.9") is True
        assert _is_suspicious_ssh_client("OpenSSH_9.0") is False
        assert _is_suspicious_ssh_client("") is False


class TestG7Stagemap:
    def test_http_anomaly_maps_to_access(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("suricata_http_anomaly") == "access"

    def test_tls_anomaly_maps_to_lateral(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("suricata_tls_anomaly") == "lateral"

    def test_ssh_anomaly_maps_to_access(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("suricata_ssh_anomaly") == "access"
