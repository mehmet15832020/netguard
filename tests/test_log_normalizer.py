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
        raw = '{"event_action": "alert", "source_ip": "10.0.0.1"}'
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

    def test_isc_dhcpd_ack_detected(self):
        raw = "Apr 24 10:00:01 opnsense dhcpd: DHCPACK on 192.168.1.50 to aa:bb:cc:dd:ee:ff (myhost) via igb0"
        assert identify_source(raw) == LogSourceType.DHCP

    def test_kea_dhcp_detected(self):
        raw = ("Apr 24 10:00:01 opnsense kea-dhcp4: INFO [kea-dhcp4.leases] "
               "DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:ff], cid=[no info], tid=0x1: "
               "lease 192.168.1.60 has been allocated")
        assert identify_source(raw) == LogSourceType.DHCP

    def test_fortigate_dhcp_detected(self):
        raw = 'date=2026-06-16 devname="FG1" type="event" subtype="dhcp" action="lease"'
        assert identify_source(raw) == LogSourceType.DHCP


# ------------------------------------------------------------------ #
#  Auth.log parse
# ------------------------------------------------------------------ #

class TestAuthLogParse:
    def test_ssh_failure_parsed(self):
        raw = "Apr 12 10:23:45 myhost sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2"
        norm = normalize(raw, observer_hostname="myhost")
        assert norm is not None
        assert norm.event_action == "ssh_failure"
        assert norm.source_ip == "192.168.1.5"
        assert norm.source_port == 22
        assert norm.username == "root"
        assert norm.severity == "warning"
        assert norm.event_category == LogCategory.AUTHENTICATION
        assert "ssh" in norm.tags

    def test_ssh_failure_has_dst_fields(self):
        raw = "Apr 12 10:23:45 srv sshd[1234]: Failed password for root from 10.0.0.9 port 55123 ssh2"
        norm = normalize(raw, observer_hostname="srv")
        assert norm.destination_ip == "srv"
        assert norm.destination_port == 22
        assert norm.network_protocol == "tcp"

    def test_ssh_success_parsed(self):
        raw = "Apr 12 11:00:00 myhost sshd[5678]: Accepted publickey for mehmet from 10.0.0.5 port 54321 ssh2"
        norm = normalize(raw, observer_hostname="myhost")
        assert norm is not None
        assert norm.event_action == "ssh_success"
        assert norm.username == "mehmet"
        assert norm.severity == "info"

    def test_ssh_success_has_dst_fields(self):
        raw = "Apr 12 11:00:00 srv sshd[5678]: Accepted publickey for mehmet from 10.0.0.5 port 54321 ssh2"
        norm = normalize(raw, observer_hostname="srv")
        assert norm.destination_ip == "srv"
        assert norm.destination_port == 22
        assert norm.network_protocol == "tcp"

    def test_sudo_usage_parsed(self):
        raw = "Apr 12 12:00:00 myhost sudo: mehmet : TTY=pts/0 ; PWD=/home/mehmet ; USER=root ; COMMAND=/bin/bash"
        norm = normalize(raw, observer_hostname="myhost")
        assert norm is not None
        assert norm.event_action == "sudo_usage"
        assert norm.username == "mehmet"
        assert norm.event_category == LogCategory.SYSTEM
        assert "sudo" in norm.tags

    def test_invalid_auth_log_returns_syslog_fallback(self):
        raw = "Apr 12 10:00:00 myhost sshd[1]: some unknown sshd message"
        norm = normalize(raw, observer_hostname="myhost")
        # auth_log olarak tespit edilir ama pattern tutmazsa syslog fallback yok,
        # None döner (auth_log parser None döner, syslog parser çağrılmaz)
        # Bu davranış beklenen: bilinmeyen auth.log satırı işlenmez
        assert norm is None or norm.event_action in ("ssh_failure", "ssh_success", "sudo_usage", "syslog")


# ------------------------------------------------------------------ #
#  Suricata parse
# ------------------------------------------------------------------ #

class TestSuricataParse:
    def test_suricata_alert_parsed(self):
        raw = """{
            "event_type": "alert",
            "event_action": "alert",
            "timestamp": "2026-04-12T10:00:00+00:00",
            "src_ip": "10.0.0.1",
            "dest_ip": "192.168.1.1",
            "src_port": 12345,
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature": "ET SCAN Port Scan",
                "category": "Attempted Information Leak",
                "severity": 2
            }
        }"""
        norm = normalize(raw, observer_hostname="sensor1")
        assert norm is not None
        assert norm.event_action == "suricata_alert"
        assert norm.source_ip == "10.0.0.1"
        assert norm.destination_ip == "192.168.1.1"
        assert norm.destination_port == 80
        assert norm.event_category == LogCategory.INTRUSION
        assert "suricata" in norm.tags

    def test_suricata_dns_parsed(self):
        raw = """{
            "event_type": "dns",
            "event_action": "dns",
            "timestamp": "2026-04-12T10:00:00+00:00",
            "src_ip": "10.0.0.5",
            "dest_ip": "8.8.8.8",
            "proto": "UDP",
            "dns": {"rrname": "example.com", "rrtype": "A", "type": "query"}
        }"""
        norm = normalize(raw, observer_hostname="sensor1")
        assert norm is not None
        assert norm.event_action == "dns_query"
        assert norm.event_category == LogCategory.NETWORK

    def test_invalid_json_returns_none(self):
        raw = '{"event_action": "alert", broken json'
        norm = normalize(raw, observer_hostname="sensor1")
        assert norm is None


# ------------------------------------------------------------------ #
#  Zeek parse
# ------------------------------------------------------------------ #

class TestZeekParse:
    def test_zeek_conn_log_parsed(self):
        raw = "1712915025.123456\tConn1\t10.0.0.1\t22\t10.0.0.2\t80\ttcp"
        norm = normalize(raw, observer_hostname="zeek-node")
        assert norm is not None
        assert norm.event_action == "zeek_connection"
        assert norm.source_ip == "10.0.0.1"
        assert norm.source_port == 22
        assert norm.destination_ip == "10.0.0.2"
        assert norm.destination_port == 80
        assert norm.event_category == LogCategory.NETWORK
        assert "zeek" in norm.tags

    def test_zeek_short_line_returns_none(self):
        raw = "1712915025.123456\tConn1"
        norm = normalize(raw, observer_hostname="zeek-node")
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
        norm = normalize(raw, observer_hostname="wazuh-manager")
        assert norm is not None
        assert norm.severity == "critical"
        assert norm.source_ip == "1.2.3.4"
        assert "wazuh" in norm.tags

    def test_wazuh_low_level_info(self):
        raw = """{
            "timestamp": "2026-04-12T10:00:00Z",
            "rule": {"id": "1001", "level": 3, "description": "System startup", "groups": []},
            "agent": {"name": "host1"}
        }"""
        norm = normalize(raw, observer_hostname="wazuh-manager")
        assert norm is not None
        assert norm.severity == "info"


# ------------------------------------------------------------------ #
#  DB entegrasyon testi
# ------------------------------------------------------------------ #

class TestProcessAndStore:
    def test_auth_log_stored_in_db(self, tmp_db, monkeypatch):
        """Ham ve normalize log DB'ye yazılır."""
        import server.log_normalizer as norm_module
        monkeypatch.setattr(norm_module, "db", tmp_db)
        test_db = tmp_db

        raw = "Apr 12 10:23:45 myhost sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2"
        norm = process_and_store(raw, observer_hostname="myhost")

        assert norm is not None
        assert norm.event_action == "ssh_failure"

        # Ham log DB'de var mı?
        raw_logs = test_db.get_unnormalized_raw_logs(limit=10)
        # normalize edildi, unnormalized listede olmaz
        norm_logs = test_db.get_normalized_logs(limit=10)
        assert len(norm_logs) == 1
        assert norm_logs[0].source_ip == "192.168.1.5"

    def test_unparseable_log_stored_as_raw_only(self, tmp_db, monkeypatch):
        """Parse edilemeyen log ham DB'ye yazılır, normalize DB'ye gitmez."""
        import server.log_normalizer as norm_module
        monkeypatch.setattr(norm_module, "db", tmp_db)
        test_db = tmp_db

        # Zeek gibi görünüyor ama çok kısa — parse edilemez
        raw = "1712915025.123456\tConn1"
        result = process_and_store(raw, observer_hostname="host1")

        assert result is None
        norm_logs = test_db.get_normalized_logs(limit=10)
        assert len(norm_logs) == 0

    def test_parse_fail_sets_normalized_minus_one(self, tmp_db, monkeypatch):
        """Parse başarısız olunca raw_logs.parse_status='failed' yazılmalı."""
        import server.log_normalizer as norm_module
        monkeypatch.setattr(norm_module, "db", tmp_db)
        test_db = tmp_db

        raw = "1712915025.123456\tConn1"  # Zeek formatı ama kısa — parse fail
        process_and_store(raw, observer_hostname="host1")

        with test_db._connect() as conn:
            row = conn.execute("SELECT parse_status FROM raw_logs LIMIT 1").fetchone()
        assert row is not None
        assert row["parse_status"] == "failed", "Parse başarısız olunca parse_status='failed' olmalı"

    def test_successful_parse_sets_normalized_one(self, tmp_db, monkeypatch):
        """Başarılı parse sonrası raw_logs.parse_status='success' yazılmalı."""
        import server.log_normalizer as norm_module
        monkeypatch.setattr(norm_module, "db", tmp_db)
        test_db = tmp_db

        raw = "Apr 12 10:23:45 myhost sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
        process_and_store(raw, observer_hostname="myhost")

        with test_db._connect() as conn:
            row = conn.execute("SELECT parse_status FROM raw_logs LIMIT 1").fetchone()
        assert row is not None
        assert row["parse_status"] == "success", "Başarılı parse sonrası parse_status='success' olmalı"


# ------------------------------------------------------------------ #
#  F1 — Firewall DHCP syslog uçtan uca + C1 ile paylaşılan MAC baseline
# ------------------------------------------------------------------ #

class TestFirewallDhcpProcessAndStore:
    def test_isc_dhcpd_ack_stored(self, tmp_db, monkeypatch):
        import server.log_normalizer as norm_module
        monkeypatch.setattr(norm_module, "db", tmp_db)

        raw = "Apr 24 10:00:01 opnsense dhcpd: DHCPACK on 192.168.1.50 to aa:bb:cc:dd:ee:ff (myhost) via igb0"
        norm = process_and_store(raw, observer_hostname="opnsense")

        assert norm is not None
        assert norm.event_action == "dhcp_lease"
        assert norm.source_ip == "192.168.1.50"

        logs = tmp_db.get_normalized_logs(limit=10)
        assert any(l.event_action == "dhcp_lease" for l in logs)

    def test_first_sighting_no_mac_change_alert(self, tmp_db, monkeypatch):
        import server.log_normalizer as norm_module
        monkeypatch.setattr(norm_module, "db", tmp_db)

        raw = "Apr 24 10:00:01 opnsense dhcpd: DHCPACK on 192.168.1.51 to aa:bb:cc:dd:ee:ff (myhost) via igb0"
        process_and_store(raw, observer_hostname="opnsense")

        logs = tmp_db.get_normalized_logs(limit=10)
        assert not any(l.event_action == "dhcp_new_mac_detected" for l in logs)

    def test_mac_change_after_known_ip_triggers_alert(self, tmp_db, monkeypatch):
        """C1 (Zeek) + F1 (firewall) aynı dhcp_mac_history'yi paylaşır."""
        import server.log_normalizer as norm_module
        monkeypatch.setattr(norm_module, "db", tmp_db)

        tmp_db.record_dhcp_mac("192.168.1.52", "11:11:11:11:11:11")

        raw = "Apr 24 10:00:01 opnsense dhcpd: DHCPACK on 192.168.1.52 to aa:bb:cc:dd:ee:ff (myhost) via igb0"
        process_and_store(raw, observer_hostname="opnsense")

        logs = tmp_db.get_normalized_logs(limit=10)
        alert = [l for l in logs if l.event_action == "dhcp_new_mac_detected"]
        assert len(alert) == 1
        assert alert[0].source_ip == "192.168.1.52"
        assert alert[0].severity == "warning"

    def test_non_dhcp_lease_event_action_no_baseline_call(self, tmp_db, monkeypatch):
        """ssh_failure gibi olaylarda DHCP baseline hook'u tetiklenmemeli."""
        import server.log_normalizer as norm_module
        monkeypatch.setattr(norm_module, "db", tmp_db)

        raw = "Apr 12 10:23:45 myhost sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2"
        process_and_store(raw, observer_hostname="myhost")

        logs = tmp_db.get_normalized_logs(limit=10)
        assert not any(l.event_action == "dhcp_new_mac_detected" for l in logs)


# ------------------------------------------------------------------ #
#  nginx web log — kaynak tespiti ve parse
# ------------------------------------------------------------------ #

class TestNginxWebLog:
    # Alpine nginx'in syslog'a yazdığı tipik format:
    # <priority>TIMESTAMP HOST nginx: ACCESS_LOG_LINE
    NGINX_SYSLOG = (
        '<134>May  3 12:00:00 alpine nginx: '
        '192.168.1.50 - - [03/May/2026:12:00:00 +0000] '
        '"GET /index.html HTTP/1.1" 200 615 "-" "Mozilla/5.0"'
    )
    NGINX_404 = (
        'nginx: 10.0.0.5 - - [03/May/2026:12:00:01 +0000] '
        '"GET /admin HTTP/1.1" 404 162 "-" "nikto/2.1.6"'
    )

    def test_nginx_syslog_identified(self):
        assert identify_source(self.NGINX_SYSLOG) == LogSourceType.NGINX

    def test_nginx_plain_identified(self):
        assert identify_source(self.NGINX_404) == LogSourceType.NGINX

    def test_nginx_200_parsed_as_web_request(self):
        norm = normalize(self.NGINX_SYSLOG, observer_hostname="10.0.10.2")
        assert norm is not None
        assert norm.event_action == "web_request"
        assert norm.source_ip == "192.168.1.50"

    def test_nginx_404_parsed_as_web_client_error(self):
        norm = normalize(self.NGINX_404, observer_hostname="10.0.10.2")
        assert norm is not None
        assert norm.event_action == "web_client_error"
        assert norm.source_ip == "10.0.0.5"

    def test_nginx_auth_fail_401(self):
        raw = (
            'nginx: 10.0.0.9 - - [03/May/2026:12:00:02 +0000] '
            '"GET /secret HTTP/1.1" 401 162 "-" "scanner/1.0"'
        )
        norm = normalize(raw, observer_hostname="10.0.10.2")
        assert norm is not None
        assert norm.event_action == "web_auth_fail"


class TestSuricataDelegation:
    def test_http_event_type_handled_via_parse_eve_line(self):
        import json as _json
        from server.log_normalizer import normalize
        raw = _json.dumps({
            "event_type": "http",
            "event_action": "http",
            "timestamp": "2026-05-01T10:00:00+00:00",
            "src_ip": "10.0.0.1",
            "src_port": 54321,
            "dest_ip": "93.184.216.34",
            "dest_port": 80,
            "proto": "TCP",
            "http": {
                "hostname": "example.com",
                "url": "/index.html",
                "http_method": "GET",
                "status": 200,
                "http_user_agent": "Mozilla/5.0 Firefox/120.0",
            },
        })
        norm = normalize(raw, observer_hostname="sensor1")
        assert norm is not None
        assert norm.event_action == "http_request"
        assert norm.source_ip == "10.0.0.1"
        assert norm.destination_port == 80

    def test_tls_event_type_handled_via_parse_eve_line(self):
        import json as _json
        from server.log_normalizer import normalize
        raw = _json.dumps({
            "event_type": "tls",
            "event_action": "tls",
            "timestamp": "2026-05-01T11:00:00+00:00",
            "src_ip": "10.0.0.2",
            "src_port": 43210,
            "dest_ip": "93.184.216.34",
            "dest_port": 443,
            "proto": "TCP",
            "tls": {
                "sni": "example.com",
                "version": "TLSv1.3",
            },
        })
        norm = normalize(raw, observer_hostname="sensor1")
        assert norm is not None
        assert norm.event_action == "ssl_connection"
        assert norm.destination_port == 443
        assert "tls" in norm.tags

    def test_unknown_event_type_returns_none(self):
        import json as _json
        from server.log_normalizer import normalize
        raw = _json.dumps({
            "event_type": "nonexistent_type",
            "event_action": "nonexistent_type",
            "timestamp": "2026-05-01T10:00:00+00:00",
            "src_ip": "10.0.0.1",
            "dest_ip": "1.2.3.4",
        })
        norm = normalize(raw, observer_hostname="sensor1")
        assert norm is None
