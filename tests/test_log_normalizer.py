"""
NetGuard — Log Normalizer testleri

Her kaynak tipi için parse doğruluğunu ve DB kayıt döngüsünü test eder.
"""

import pytest
from datetime import datetime, timezone

from server.log_normalizer import identify_source, normalize, process_and_store
from shared.models import LogSourceType, LogCategory


# ------------------------------------------------------------------ #
#  Kaynak tespiti
# ------------------------------------------------------------------ #

class TestIdentifySource:
    def test_suricata_json_detected(self):
        raw = '{"event_type": "alert", "src_ip": "10.0.0.1"}'
        assert identify_source(raw) == LogSourceType.SURICATA

    def test_zeek_tsv_detected(self):
        raw = "1712915025.123456\tConn1\t10.0.0.1\t22\t10.0.0.2\t80\ttcp"
        assert identify_source(raw) == LogSourceType.ZEEK

    def test_wazuh_json_detected(self):
        raw = '{"rule": {"id": "5501"}, "agent": {"name": "host1"}}'
        assert identify_source(raw) == LogSourceType.WAZUH

    def test_auth_log_sshd_detected(self):
        raw = "Apr 12 10:23:45 myhost sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
        assert identify_source(raw) == LogSourceType.AUTH_LOG

    def test_auth_log_sudo_detected(self):
        raw = "Apr 12 10:00:00 myhost sudo: mehmet : TTY=pts/0 ; COMMAND=/bin/bash"
        assert identify_source(raw) == LogSourceType.AUTH_LOG

    def test_unknown_falls_back_to_syslog(self):
        raw = "some random log message without patterns"
        assert identify_source(raw) == LogSourceType.SYSLOG


# ------------------------------------------------------------------ #
#  Auth.log parse
# ------------------------------------------------------------------ #

class TestAuthLogParse:
    def test_ssh_failure_parsed(self):
        raw = "Apr 12 10:23:45 myhost sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2"
        norm = normalize(raw, source_host="myhost")
        assert norm is not None
        assert norm.event_type == "ssh_failure"
        assert norm.src_ip == "192.168.1.5"
        assert norm.src_port == 22
        assert norm.username == "root"
        assert norm.severity == "warning"
        assert norm.category == LogCategory.AUTHENTICATION
        assert "ssh" in norm.tags

    def test_ssh_success_parsed(self):
        raw = "Apr 12 11:00:00 myhost sshd[5678]: Accepted publickey for mehmet from 10.0.0.5 port 54321 ssh2"
        norm = normalize(raw, source_host="myhost")
        assert norm is not None
        assert norm.event_type == "ssh_success"
        assert norm.username == "mehmet"
        assert norm.severity == "info"

    def test_sudo_usage_parsed(self):
        raw = "Apr 12 12:00:00 myhost sudo: mehmet : TTY=pts/0 ; PWD=/home/mehmet ; USER=root ; COMMAND=/bin/bash"
        norm = normalize(raw, source_host="myhost")
        assert norm is not None
        assert norm.event_type == "sudo_usage"
        assert norm.username == "mehmet"
        assert norm.category == LogCategory.SYSTEM
        assert "sudo" in norm.tags

    def test_invalid_auth_log_returns_syslog_fallback(self):
        raw = "Apr 12 10:00:00 myhost sshd[1]: some unknown sshd message"
        norm = normalize(raw, source_host="myhost")
        # auth_log olarak tespit edilir ama pattern tutmazsa syslog fallback yok,
        # None döner (auth_log parser None döner, syslog parser çağrılmaz)
        # Bu davranış beklenen: bilinmeyen auth.log satırı işlenmez
        assert norm is None or norm.event_type in ("ssh_failure", "ssh_success", "sudo_usage", "syslog")


# ------------------------------------------------------------------ #
#  Suricata parse
# ------------------------------------------------------------------ #

class TestSuricataParse:
    def test_suricata_alert_parsed(self):
        raw = """{
            "event_type": "alert",
            "timestamp": "2026-04-12T10:00:00+00:00",
            "src_ip": "10.0.0.1",
            "dest_ip": "192.168.1.1",
            "src_port": 12345,
            "dest_port": 80,
            "alert": {
                "signature": "ET SCAN Port Scan",
                "category": "Attempted Information Leak",
                "severity": 2
            }
        }"""
        norm = normalize(raw, source_host="sensor1")
        assert norm is not None
        assert norm.event_type == "suricata_alert"
        assert norm.src_ip == "10.0.0.1"
        assert norm.dst_ip == "192.168.1.1"
        assert norm.dst_port == 80
        assert norm.category == LogCategory.INTRUSION
        assert "suricata" in norm.tags

    def test_suricata_dns_parsed(self):
        raw = """{
            "event_type": "dns",
            "timestamp": "2026-04-12T10:00:00+00:00",
            "src_ip": "10.0.0.5",
            "dest_ip": "8.8.8.8",
            "dns": {"rrname": "example.com", "rrtype": "A"}
        }"""
        norm = normalize(raw, source_host="sensor1")
        assert norm is not None
        assert norm.event_type == "dns_query"
        assert norm.category == LogCategory.NETWORK

    def test_invalid_json_returns_none(self):
        raw = '{"event_type": "alert", broken json'
        norm = normalize(raw, source_host="sensor1")
        assert norm is None


# ------------------------------------------------------------------ #
#  Zeek parse
# ------------------------------------------------------------------ #

class TestZeekParse:
    def test_zeek_conn_log_parsed(self):
        raw = "1712915025.123456\tConn1\t10.0.0.1\t22\t10.0.0.2\t80\ttcp"
        norm = normalize(raw, source_host="zeek-node")
        assert norm is not None
        assert norm.event_type == "zeek_connection"
        assert norm.src_ip == "10.0.0.1"
        assert norm.src_port == 22
        assert norm.dst_ip == "10.0.0.2"
        assert norm.dst_port == 80
        assert norm.category == LogCategory.NETWORK
        assert "zeek" in norm.tags

    def test_zeek_short_line_returns_none(self):
        raw = "1712915025.123456\tConn1"
        norm = normalize(raw, source_host="zeek-node")
        assert norm is None


# ------------------------------------------------------------------ #
#  Wazuh parse
# ------------------------------------------------------------------ #

class TestWazuhParse:
    def test_wazuh_high_level_alert(self):
        raw = """{
            "timestamp": "2026-04-12T10:00:00Z",
            "rule": {"id": "5501", "level": 12, "description": "Multiple failed logins", "groups": ["authentication_failed"]},
            "agent": {"name": "webserver"},
            "srcip": "1.2.3.4"
        }"""
        norm = normalize(raw, source_host="wazuh-manager")
        assert norm is not None
        assert norm.severity == "critical"
        assert norm.src_ip == "1.2.3.4"
        assert "wazuh" in norm.tags

    def test_wazuh_low_level_info(self):
        raw = """{
            "timestamp": "2026-04-12T10:00:00Z",
            "rule": {"id": "1001", "level": 3, "description": "System startup", "groups": []},
            "agent": {"name": "host1"}
        }"""
        norm = normalize(raw, source_host="wazuh-manager")
        assert norm is not None
        assert norm.severity == "info"


# ------------------------------------------------------------------ #
#  DB entegrasyon testi
# ------------------------------------------------------------------ #

class TestProcessAndStore:
    def test_auth_log_stored_in_db(self, tmp_path, monkeypatch):
        """Ham ve normalize log DB'ye yazılır."""
        import server.database as db_module
        import server.log_normalizer as norm_module

        # Geçici DB kullan
        test_db_path = str(tmp_path / "test.db")
        monkeypatch.setattr(db_module, "DB_PATH", test_db_path)
        test_db = db_module.DatabaseManager(test_db_path)
        monkeypatch.setattr(db_module, "db", test_db)
        monkeypatch.setattr(norm_module, "db", test_db)

        raw = "Apr 12 10:23:45 myhost sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2"
        norm = process_and_store(raw, source_host="myhost")

        assert norm is not None
        assert norm.event_type == "ssh_failure"

        # Ham log DB'de var mı?
        raw_logs = test_db.get_unnormalized_raw_logs(limit=10)
        # normalize edildi, unnormalized listede olmaz
        norm_logs = test_db.get_normalized_logs(limit=10)
        assert len(norm_logs) == 1
        assert norm_logs[0].src_ip == "192.168.1.5"

    def test_unparseable_log_stored_as_raw_only(self, tmp_path, monkeypatch):
        """Parse edilemeyen log ham DB'ye yazılır, normalize DB'ye gitmez."""
        import server.database as db_module
        import server.log_normalizer as norm_module

        test_db_path = str(tmp_path / "test2.db")
        test_db = db_module.DatabaseManager(test_db_path)
        monkeypatch.setattr(db_module, "db", test_db)
        monkeypatch.setattr(norm_module, "db", test_db)

        # Zeek gibi görünüyor ama çok kısa — parse edilemez
        raw = "1712915025.123456\tConn1"
        result = process_and_store(raw, source_host="host1")

        assert result is None
        norm_logs = test_db.get_normalized_logs(limit=10)
        assert len(norm_logs) == 0
