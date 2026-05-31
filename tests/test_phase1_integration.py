"""
Faz 1 — Veri Zenginleştirme Entegrasyon Testleri

Birim testler her parser'ı izole test eder.
Bu dosya ÇAPRAZ (cross-cutting) ve ENTEGRASYON testleri içerir:

  1. JA3 Pipeline  — ssl.log → parse_ssl → normalized_logs → sigma_executor
  2. x509 Pipeline — x509.log → parse_x509 → normalized_logs → self-signed alert
  3. FTP Pipeline  — ftp.log → parse_ftp → normalized_logs → sigma burst rule
  4. SMTP Pipeline — smtp.log → parse_smtp → normalized_logs → sigma bulk send rule
  5. Agent Conn    — suspicious psutil conn → log_shipper event → security route
  6. Zeek Multi-Log — aynı session birden fazla log türü → doğru olay zincirlenmesi
  7. Sigma Yük     — tüm sigma_rules_v2/*.yml pySigma ile yüklenebilmeli
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from server.parsers.zeek import (
    parse_ssl, parse_x509, parse_smtp, parse_ftp,
    _KNOWN_BAD_JA3,
)
from server.sigma_executor import SigmaExecutor
from shared.models import LogSourceType, LogCategory


# ─────────────────────────────────────────────────────────────────────────────
#  Fixture — izole in-memory SQLite
# ─────────────────────────────────────────────────────────────────────────────



@pytest.fixture()
def sigma_ex():
    """Gerçek sigma_rules_v2 dizininden yüklü SigmaExecutor."""
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    return SigmaExecutor(str(rules_dir))


def _insert_event(conn, event_action, source_ip="1.2.3.4",
                  severity="info", minutes_ago=0,
                  message="test", source_type="zeek"):
    from datetime import datetime, timezone, timedelta
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    conn.execute(
        """
        INSERT INTO normalized_logs
          (log_id, event_action, source_ip, timestamp, message, severity, tenant_id, source_type)
        VALUES (%s, %s, %s, %s, %s, %s, 'default', %s)
        """,
        (str(uuid.uuid4()), event_action, source_ip, ts, message, severity, source_type),
    )
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
#  1. JA3 Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestJA3Pipeline:
    """ssl.log satırı → parse_ssl → normalized_logs → sigma_executor."""

    def test_bad_ja3_parse_result(self):
        """Bilinen kötü JA3 → critical severity, özel event_action."""
        bad_ja3 = next(iter(_KNOWN_BAD_JA3))
        row = {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "185.220.101.45",
            "id.resp_p": 443,
            "server_name": "-",
            "validation_status": "ok",
            "ja3": bad_ja3,
            "ja3s": "",
        }
        log = parse_ssl(row)
        assert log is not None
        assert log.severity == "critical"
        assert log.event_action == "tls_suspicious_fingerprint"
        assert log.extra.get("ja3") == bad_ja3
        assert "KNOWN_MALWARE_JA3" in log.message

    def test_good_ja3_normal_event(self):
        """İyi JA3 → normal ssl_connection, info severity."""
        row = {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "1.2.3.4",
            "id.resp_p": 443,
            "server_name": "google.com",
            "validation_status": "ok",
            "ja3": "aabbccddeeff00112233445566778899",
        }
        log = parse_ssl(row)
        assert log is not None
        assert log.severity == "info"
        assert log.event_action == "ssl_connection"

    def test_ja3_sigma_rule_detects_fingerprint(self, mem_db, sigma_ex):
        """tls_suspicious_fingerprint event'i → TLS JA3 sigma kuralı tetiklenir."""
        _insert_event(mem_db, "tls_suspicious_fingerprint",
                      source_ip="10.0.0.5", severity="critical")

        ja3_rule = next(
            (r for r in sigma_ex.rules
             if "ja3" in r.title.lower() or "fingerprint" in r.title.lower()),
            None,
        )
        assert ja3_rule is not None, "TLS JA3 sigma kuralı bulunamadı"

        rows = sigma_ex.execute_rule(ja3_rule, mem_db)
        assert len(rows) >= 1, "JA3 kötü fingerprint sigma kuralı eşleşmeli"

    def test_ja3_self_signed_burst_triggers_sigma(self, mem_db, sigma_ex):
        """3+ self-signed SSL aynı IP'den 10 dk içinde → SSL burst kuralı tetiklenir."""
        ssl_burst_rule = next(
            (r for r in sigma_ex.rules
             if r.title.lower() == "ssl self-signed certificate burst"),
            None,
        )
        if ssl_burst_rule is None:
            pytest.skip("SSL self-signed burst kuralı yok")

        for _ in range(4):
            _insert_event(
                mem_db, "ssl_connection",
                source_ip="10.0.0.5",
                message="SSL/TLS 10.0.0.1 SELF-SIGNED",
            )

        rows = sigma_ex.execute_rule(ssl_burst_rule, mem_db)
        assert len(rows) >= 1


# ─────────────────────────────────────────────────────────────────────────────
#  2. x509 Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestX509Pipeline:
    def test_self_signed_parse(self):
        same = "CN=attacker.local"
        row = {
            "ts": 1700000000.0,
            "certificate": {"subject": same, "issuer": same},
        }
        log = parse_x509(row)
        assert log.severity == "warning"
        assert "SELF-SIGNED" in log.message
        assert log.extra["self_signed"] is True

    def test_legitimate_cert_info(self):
        row = {
            "ts": 1700000000.0,
            "certificate": {
                "subject": "CN=api.github.com,O=GitHub",
                "issuer": "CN=DigiCert TLS RSA SHA256 2020 CA1",
            },
        }
        log = parse_x509(row)
        assert log.severity == "info"
        assert log.extra["self_signed"] is False
        assert "DigiCert" in log.message

    def test_missing_cert_dict(self):
        row = {"ts": 1700000000.0, "certificate": "-"}
        log = parse_x509(row)
        assert log is not None
        assert log.event_action == "x509_certificate"

    def test_x509_tags(self):
        row = {
            "ts": 1700000000.0,
            "certificate": {
                "subject": "CN=evil.local",
                "issuer": "CN=evil.local",
            },
        }
        log = parse_x509(row)
        assert "self_signed" in log.tags
        assert "x509" in log.tags


# ─────────────────────────────────────────────────────────────────────────────
#  3. FTP Exfiltration Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestFTPPipeline:
    def test_retr_command_warning(self):
        row = {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.0.100",
            "id.resp_h": "192.168.1.200",
            "id.resp_p": 21,
            "command": "RETR",
            "arg": "passwords.db",
            "reply_code": 226,
            "user": "anonymous",
        }
        log = parse_ftp(row)
        assert log.severity == "warning"
        assert "ftp_sensitive" in log.tags
        assert "RETR" in log.message
        assert "passwords.db" in log.message

    def test_stor_upload_warning(self):
        row = {
            "ts": 1700000000.0,
            "id.orig_h": "10.0.0.100",
            "id.resp_h": "5.5.5.5",
            "id.resp_p": 21,
            "command": "STOR",
            "arg": "malware.exe",
            "reply_code": 226,
            "user": "ftpuser",
        }
        log = parse_ftp(row)
        assert log.severity == "warning"
        assert log.extra["command"] == "STOR"

    def test_ftp_burst_sigma_rule(self, mem_db, sigma_ex):
        """10+ FTP sensitive komut 10 dk içinde → FTP exfiltration sigma tetiklenir."""
        ftp_rule = next(
            (r for r in sigma_ex.rules if "ftp" in r.title.lower()),
            None,
        )
        if ftp_rule is None:
            pytest.skip("FTP sigma kuralı bulunamadı")

        for _ in range(12):
            _insert_event(
                mem_db, "ftp_command",
                source_ip="10.0.0.100",
                message="FTP RETR user=anonymous arg=data.zip ftp_sensitive",
            )

        rows = sigma_ex.execute_rule(ftp_rule, mem_db)
        assert len(rows) >= 1
        assert rows[0]["event_count"] >= 10

    def test_list_command_info(self):
        row = {
            "ts": 1700000000.0,
            "id.orig_h": "1.2.3.4",
            "id.resp_h": "5.6.7.8",
            "id.resp_p": 21,
            "command": "LIST",
            "arg": "/",
            "reply_code": 226,
            "user": "ftpuser",
        }
        log = parse_ftp(row)
        assert log.severity == "info"
        assert "ftp_sensitive" not in log.tags


# ─────────────────────────────────────────────────────────────────────────────
#  4. SMTP Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestSMTPPipeline:
    def test_basic_smtp_parse(self):
        row = {
            "ts": 1700000000.0,
            "id.orig_h": "192.168.1.10",
            "id.resp_h": "10.0.0.25",
            "id.resp_p": 25,
            "mailfrom": "attacker@evil.com",
            "rcptto": ["victim@company.com"],
            "subject": "Urgent Invoice",
        }
        log = parse_smtp(row)
        assert log is not None
        assert log.event_action == "smtp_session"
        assert "attacker@evil.com" in log.message
        assert log.destination_port == 25

    def test_smtp_bulk_sigma_rule(self, mem_db, sigma_ex):
        """20+ SMTP session 10 dk içinde → SMTP bulk send sigma tetiklenir."""
        smtp_rule = next(
            (r for r in sigma_ex.rules if "smtp" in r.title.lower()),
            None,
        )
        if smtp_rule is None:
            pytest.skip("SMTP sigma kuralı bulunamadı")

        for _ in range(22):
            _insert_event(
                mem_db, "smtp_session",
                source_ip="10.0.0.10",
                message="SMTP from=bot@spam.com to=victim@company.com",
            )

        rows = sigma_ex.execute_rule(smtp_rule, mem_db)
        assert len(rows) >= 1
        assert rows[0]["event_count"] >= 20

    def test_no_mailfrom_rcptto_returns_none(self):
        row = {
            "ts": 1700000000.0,
            "id.orig_h": "1.2.3.4",
            "id.resp_h": "5.6.7.8",
            "id.resp_p": 25,
            "mailfrom": "-",
            "rcptto": [],
        }
        assert parse_smtp(row) is None

    def test_multiple_recipients_joined(self):
        row = {
            "ts": 1700000000.0,
            "id.orig_h": "1.2.3.4",
            "id.resp_h": "5.6.7.8",
            "id.resp_p": 25,
            "mailfrom": "spammer@evil.com",
            "rcptto": ["a@x.com", "b@x.com", "c@x.com", "d@x.com"],
            "subject": "Win a prize",
        }
        log = parse_smtp(row)
        assert log is not None
        assert "a@x.com" in log.message


# ─────────────────────────────────────────────────────────────────────────────
#  5. Agent Suspicious Connection Cross-Test
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentConnectionCross:
    """_collect_suspicious_connections() → olayların doğru sınıflandırılması."""

    def _run(self, conns, local_ip="192.168.1.10"):
        with (
            patch("agent.log_shipper.psutil.net_connections", return_value=conns),
            patch("agent.log_shipper.socket.gethostbyname", return_value=local_ip),
        ):
            from agent.log_shipper import _collect_suspicious_connections
            return _collect_suspicious_connections()

    def _conn(self, raddr_ip, raddr_port, status="ESTABLISHED", lport=54321, pid=None):
        c = MagicMock()
        c.status = status
        c.pid = pid
        c.raddr = MagicMock(ip=raddr_ip, port=raddr_port)
        c.laddr = MagicMock(port=lport)
        return c

    def test_c2_port_4444_critical(self):
        events = self._run([self._conn("185.220.101.10", 4444)])
        assert len(events) == 1
        assert events[0]["severity"] == "critical"
        assert events[0]["event_action"] == "suspicious_outbound_connection"

    def test_rdp_port_3389_critical(self):
        events = self._run([self._conn("10.0.0.50", 3389)])
        assert len(events) == 1
        assert events[0]["severity"] == "critical"

    def test_vnc_port_5900_critical(self):
        events = self._run([self._conn("10.0.0.50", 5900)])
        assert len(events) == 1
        assert events[0]["severity"] == "critical"

    def test_telnet_port_23_critical(self):
        events = self._run([self._conn("10.0.0.50", 23)])
        assert len(events) == 1
        assert events[0]["severity"] == "critical"

    def test_https_443_not_reported(self):
        events = self._run([self._conn("1.1.1.1", 443)])
        assert events == []

    def test_ssh_22_not_reported(self):
        events = self._run([self._conn("192.168.1.5", 22)])
        assert events == []

    def test_multiple_mixed_ports(self):
        conns = [
            self._conn("10.20.30.40", 4444),  # bad
            self._conn("10.20.30.40", 6667),  # bad
            self._conn("8.8.8.8", 443),       # ok
            self._conn("8.8.8.8", 80),        # ok
            self._conn("10.0.0.5", 5555),     # bad
        ]
        events = self._run(conns)
        assert len(events) == 3

    def test_process_name_in_message(self):
        conn = self._conn("10.20.30.40", 4444, pid=1234)
        with (
            patch("agent.log_shipper.psutil.net_connections", return_value=[conn]),
            patch("agent.log_shipper.socket.gethostbyname", return_value="192.168.1.10"),
            patch("agent.log_shipper.psutil.Process") as mock_proc,
        ):
            mock_proc.return_value.name.return_value = "malware.exe"
            from agent.log_shipper import _collect_suspicious_connections
            events = _collect_suspicious_connections()
        assert "malware.exe" in events[0]["message"]

    def test_access_denied_returns_empty(self):
        import psutil as _psutil
        with patch("agent.log_shipper.psutil.net_connections",
                   side_effect=_psutil.AccessDenied(0, "root")):
            from agent.log_shipper import _collect_suspicious_connections
            events = _collect_suspicious_connections()
        assert events == []


# ─────────────────────────────────────────────────────────────────────────────
#  6. Zeek Multi-Log Cross-Test
# ─────────────────────────────────────────────────────────────────────────────

class TestZeekMultiLogCross:
    """Aynı IP'den farklı Zeek logları → tutarlı parse sonuçları."""

    ATTACKER_IP = "185.220.101.45"

    def _ssl_row(self, ja3=""):
        return {
            "ts": 1700000000.0,
            "id.orig_h": self.ATTACKER_IP,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 443,
            "server_name": "c2.evil.com",
            "validation_status": "ok",
            "ja3": ja3,
        }

    def test_ssl_and_dns_same_source_ip(self):
        from server.parsers.zeek import parse_dns
        ssl_log = parse_ssl(self._ssl_row())
        dns_row = {
            "ts": 1700000001.0,
            "id.orig_h": self.ATTACKER_IP,
            "id.resp_h": "8.8.8.8",
            "proto": "udp",
            "query": "c2.evil.com",
            "qtype_name": "A",
            "answers": ["185.220.101.45"],
            "rcode_name": "NOERROR",
        }
        dns_log = parse_dns(dns_row)

        assert ssl_log.source_ip == dns_log.source_ip == self.ATTACKER_IP
        assert ssl_log.source_type == dns_log.source_type  # ikisi de ZEEK

    def test_bad_ja3_followed_by_ftp(self):
        """Bilinen kötü JA3 TLS handshake + FTP STOR = yüksek güvenceli exfil."""
        bad_ja3 = next(iter(_KNOWN_BAD_JA3))
        ssl_log = parse_ssl(self._ssl_row(ja3=bad_ja3))
        ftp_row = {
            "ts": 1700000010.0,
            "id.orig_h": self.ATTACKER_IP,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 21,
            "command": "STOR",
            "arg": "exfil.zip",
            "reply_code": 226,
            "user": "anonymous",
        }
        ftp_log = parse_ftp(ftp_row)

        assert ssl_log.severity == "critical"
        assert ftp_log.severity == "warning"
        assert ssl_log.source_ip == ftp_log.source_ip == self.ATTACKER_IP

    def test_self_signed_and_smtp(self):
        """Self-signed sertifika + SMTP → aynı kaynak IP."""
        x509_row = {
            "ts": 1700000000.0,
            "certificate": {"subject": "CN=evil.local", "issuer": "CN=evil.local"},
        }
        smtp_row = {
            "ts": 1700000005.0,
            "id.orig_h": self.ATTACKER_IP,
            "id.resp_h": "10.0.0.25",
            "id.resp_p": 25,
            "mailfrom": "attacker@evil.local",
            "rcptto": ["victim@company.com"],
            "subject": "Invoice",
        }
        x509_log = parse_x509(x509_row)
        smtp_log = parse_smtp(smtp_row)

        assert x509_log.severity == "warning"
        assert smtp_log is not None
        assert smtp_log.source_ip == self.ATTACKER_IP


# ─────────────────────────────────────────────────────────────────────────────
#  7. Sigma Kuralı Yükleme — Tüm Dosyalar
# ─────────────────────────────────────────────────────────────────────────────

class TestSigmaRulesLoading:
    """Tüm sigma_rules_v2/*.yml dosyaları pySigma ile yüklenebilmeli."""

    def test_all_rules_load_without_error(self):
        rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
        ex = SigmaExecutor(str(rules_dir))
        assert len(ex.rules) >= 20, f"En az 20 kural bekleniyor, {len(ex.rules)} yüklendi"

    def test_network_community_rules_present(self):
        rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
        ex = SigmaExecutor(str(rules_dir))
        titles = {r.title for r in ex.rules}
        expected = {
            "DNS Tunneling — High TXT Query Rate",
            "FTP Exfiltration Burst",
            "ARP Spoofing Burst",
            "Lateral Movement Spread",
            "Sudo Command Abuse",
        }
        missing = expected - titles
        assert not missing, f"Eksik kurallar: {missing}"

    def test_ja3_rule_present_and_correlation_false(self):
        rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
        ex = SigmaExecutor(str(rules_dir))
        ja3_rule = next(
            (r for r in ex.rules if "ja3" in r.title.lower() or "fingerprint" in r.title.lower()),
            None,
        )
        assert ja3_rule is not None
        assert ja3_rule.is_correlation is False
        assert ja3_rule.severity == "critical"

    def test_all_correlation_rules_have_window(self):
        rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
        ex = SigmaExecutor(str(rules_dir))
        for r in ex.rules:
            if r.is_correlation:
                assert r.window_seconds > 0, f"{r.title}: window_seconds=0"
                assert r.group_by_fields, f"{r.title}: group_by_fields boş"

    def test_all_rules_have_valid_severity(self):
        rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
        ex = SigmaExecutor(str(rules_dir))
        valid = {"info", "warning", "high", "critical"}
        for r in ex.rules:
            assert r.severity in valid, f"{r.title}: geçersiz severity={r.severity}"

    def test_all_rules_sql_references_normalized_logs(self):
        rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
        ex = SigmaExecutor(str(rules_dir))
        for r in ex.rules:
            assert "normalized_logs" in r.sql, (
                f"{r.title}: SQL'de normalized_logs yok → {r.sql[:80]}"
            )

    def test_ja3_sigma_executes_on_real_data(self, mem_db):
        """JA3 sigma kuralı gerçek event_action ile eşleşir."""
        rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
        ex = SigmaExecutor(str(rules_dir))
        ja3_rule = next(
            (r for r in ex.rules if "fingerprint" in r.title.lower()), None
        )
        assert ja3_rule is not None

        _insert_event(mem_db, "tls_suspicious_fingerprint",
                      source_ip="10.0.0.5", severity="critical")
        rows = ex.execute_rule(ja3_rule, mem_db)
        assert len(rows) >= 1

    def test_ftp_sigma_executes_on_real_data(self, mem_db):
        rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
        ex = SigmaExecutor(str(rules_dir))
        ftp_rule = next((r for r in ex.rules if "ftp" in r.title.lower()), None)
        if not ftp_rule:
            pytest.skip("FTP kuralı yok")

        for _ in range(12):
            _insert_event(mem_db, "ftp_command", source_ip="10.0.0.100",
                          message="FTP RETR ftp_sensitive")

        rows = ex.execute_rule(ftp_rule, mem_db)
        assert len(rows) >= 1

    def test_arp_spoof_sigma_executes(self, mem_db):
        rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
        ex = SigmaExecutor(str(rules_dir))
        arp_rule = next((r for r in ex.rules if "arp" in r.title.lower()), None)
        if not arp_rule:
            pytest.skip("ARP kuralı yok")

        for _ in range(4):
            _insert_event(mem_db, "arp_spoof", source_ip="192.168.1.100")

        rows = ex.execute_rule(arp_rule, mem_db)
        assert len(rows) >= 1
