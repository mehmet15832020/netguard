"""
Faz 5 — Cross-Domain Correlation testleri

Her event kaynağının (auth log, SNMP trap, uptime checker)
normalized_logs tablosuna da yazdığını ve correlator'ın
bu kayıtları doğru şekilde işlediğini doğrular.
"""

import uuid
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from server.database import DatabaseManager
from server.correlator import Correlator, CorrelationRule
from shared.models import NormalizedLog, LogSourceType, LogCategory


# ------------------------------------------------------------------ #
#  Yardımcılar
# ------------------------------------------------------------------ #

def _make_rule(
    rule_id="r1",
    match_event_type="ssh_failure",
    group_by="src_ip",
    window_seconds=300,
    threshold=3,
    severity="critical",
    output_event_type="brute_force_detected",
):
    return CorrelationRule(
        rule_id=rule_id,
        name="Test",
        description="",
        match_event_type=match_event_type,
        group_by=group_by,
        window_seconds=window_seconds,
        threshold=threshold,
        severity=severity,
        output_event_type=output_event_type,
        enabled=True,
    )


def _norm_log(event_type, src_ip="1.2.3.4", source_host="host1", minutes_ago=0):
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.NETGUARD,
        source_host=source_host,
        timestamp=ts,
        severity="warning",
        category=LogCategory.NETWORK,
        event_type=event_type,
        src_ip=src_ip,
        message=f"test {event_type}",
    )


@pytest.fixture
def corr_setup(tmp_path, monkeypatch):
    import server.database as db_module
    import server.correlator as corr_module

    test_db = DatabaseManager(str(tmp_path / "test.db"))
    monkeypatch.setattr(db_module, "db", test_db)
    monkeypatch.setattr(corr_module, "db", test_db)

    c = Correlator(rules_path=str(tmp_path / "empty.json"))
    c._rules = []
    return c, test_db


# ------------------------------------------------------------------ #
#  SSH Brute Force — auth log → normalized_logs → correlator
# ------------------------------------------------------------------ #

class TestSSHBruteForceCorrelation:
    def test_ssh_failures_trigger_brute_force_rule(self, corr_setup):
        correlator, test_db = corr_setup
        correlator._rules = [_make_rule(
            match_event_type="ssh_failure", group_by="src_ip",
            threshold=3, output_event_type="brute_force_detected",
        )]

        for _ in range(3):
            test_db.save_normalized_log(_norm_log("ssh_failure", src_ip="10.0.0.5"))

        events = correlator.run()
        assert len(events) == 1
        assert events[0].event_type == "brute_force_detected"
        assert events[0].group_value == "10.0.0.5"

    def test_ssh_failures_below_threshold_no_event(self, corr_setup):
        correlator, test_db = corr_setup
        correlator._rules = [_make_rule(threshold=5)]

        for _ in range(4):
            test_db.save_normalized_log(_norm_log("ssh_failure", src_ip="10.0.0.5"))

        assert correlator.run() == []

    def test_ssh_success_not_counted_for_brute_force(self, corr_setup):
        correlator, test_db = corr_setup
        correlator._rules = [_make_rule(
            match_event_type="ssh_failure", threshold=3,
        )]

        for _ in range(3):
            test_db.save_normalized_log(_norm_log("ssh_success", src_ip="10.0.0.5"))

        assert correlator.run() == []


# ------------------------------------------------------------------ #
#  Port Scan — dedektör → normalized_logs → correlator
# ------------------------------------------------------------------ #

class TestPortScanCorrelation:
    def test_port_scan_events_trigger_rule(self, corr_setup):
        correlator, test_db = corr_setup
        correlator._rules = [_make_rule(
            rule_id="port_scan",
            match_event_type="port_scan_attempt",
            group_by="src_ip",
            threshold=3,
            output_event_type="port_scan_detected",
            severity="warning",
        )]

        for _ in range(3):
            test_db.save_normalized_log(_norm_log("port_scan_attempt", src_ip="192.168.1.99"))

        events = correlator.run()
        assert len(events) == 1
        assert events[0].event_type == "port_scan_detected"
        assert events[0].severity == "warning"


# ------------------------------------------------------------------ #
#  Device Down — uptime checker → normalized_logs → correlator
# ------------------------------------------------------------------ #

class TestDeviceDownCorrelation:
    def test_device_down_events_trigger_outage_rule(self, corr_setup):
        correlator, test_db = corr_setup
        correlator._rules = [_make_rule(
            rule_id="device_outage",
            match_event_type="device_down",
            group_by="source_host",
            threshold=2,
            output_event_type="sustained_outage_detected",
            severity="warning",
        )]

        for _ in range(2):
            test_db.save_normalized_log(
                _norm_log("device_down", source_host="router-core", src_ip="10.0.0.1")
            )

        events = correlator.run()
        assert len(events) == 1
        assert events[0].event_type == "sustained_outage_detected"
        assert events[0].group_value == "router-core"

    def test_device_up_not_counted_for_outage(self, corr_setup):
        correlator, test_db = corr_setup
        correlator._rules = [_make_rule(
            rule_id="device_outage",
            match_event_type="device_down",
            group_by="source_host",
            threshold=2,
            output_event_type="sustained_outage_detected",
        )]

        for _ in range(3):
            test_db.save_normalized_log(
                _norm_log("device_up", source_host="router-core")
            )

        assert correlator.run() == []


# ------------------------------------------------------------------ #
#  SNMP Trap — trap receiver → normalized_logs → correlator
# ------------------------------------------------------------------ #

class TestSNMPTrapCorrelation:
    def test_snmp_trap_burst_triggers_rule(self, corr_setup):
        correlator, test_db = corr_setup
        correlator._rules = [_make_rule(
            rule_id="snmp_burst",
            match_event_type="snmp_trap",
            group_by="source_host",
            threshold=5,
            output_event_type="snmp_trap_burst_detected",
            severity="warning",
        )]

        for _ in range(5):
            test_db.save_normalized_log(
                _norm_log("snmp_trap", source_host="switch-01", src_ip="10.0.0.2")
            )

        events = correlator.run()
        assert len(events) == 1
        assert events[0].event_type == "snmp_trap_burst_detected"


# ------------------------------------------------------------------ #
#  ARP Spoof — dedektör → normalized_logs → correlator
# ------------------------------------------------------------------ #

class TestARPSpoofCorrelation:
    def test_arp_spoof_triggers_critical_rule(self, corr_setup):
        correlator, test_db = corr_setup
        correlator._rules = [_make_rule(
            rule_id="arp_attack",
            match_event_type="arp_spoof_attempt",
            group_by="src_ip",
            threshold=2,
            output_event_type="arp_attack_detected",
            severity="critical",
        )]

        for _ in range(2):
            test_db.save_normalized_log(_norm_log("arp_spoof_attempt", src_ip="10.0.0.55"))

        events = correlator.run()
        assert len(events) == 1
        assert events[0].severity == "critical"
        assert events[0].event_type == "arp_attack_detected"


# ------------------------------------------------------------------ #
#  Çoklu kural — farklı domain'ler aynı anda tetiklenir
# ------------------------------------------------------------------ #

class TestMultiDomainCorrelation:
    def test_ssh_and_port_scan_from_same_ip_both_detected(self, corr_setup):
        correlator, test_db = corr_setup
        correlator._rules = [
            _make_rule(
                rule_id="ssh_bf",
                match_event_type="ssh_failure",
                group_by="src_ip",
                threshold=3,
                output_event_type="brute_force_detected",
            ),
            _make_rule(
                rule_id="port_scan",
                match_event_type="port_scan_attempt",
                group_by="src_ip",
                threshold=3,
                output_event_type="port_scan_detected",
            ),
        ]

        attacker_ip = "172.16.0.99"
        for _ in range(3):
            test_db.save_normalized_log(_norm_log("ssh_failure", src_ip=attacker_ip))
            test_db.save_normalized_log(_norm_log("port_scan_attempt", src_ip=attacker_ip))

        events = correlator.run()
        event_types = {e.event_type for e in events}
        assert "brute_force_detected" in event_types
        assert "port_scan_detected" in event_types
        assert len(events) == 2

    def test_different_attackers_tracked_independently(self, corr_setup):
        correlator, test_db = corr_setup
        correlator._rules = [_make_rule(threshold=3)]

        for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
            for _ in range(3):
                test_db.save_normalized_log(_norm_log("ssh_failure", src_ip=ip))

        events = correlator.run()
        assert len(events) == 3
        group_values = {e.group_value for e in events}
        assert group_values == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


# ------------------------------------------------------------------ #
#  security_log_parser → normalized_logs entegrasyon testi
# ------------------------------------------------------------------ #

class TestSecurityLogParserNormalization:
    def test_ssh_failure_writes_to_normalized_logs(self, tmp_path, monkeypatch):
        import server.database as db_module
        import server.security_log_parser as slp_module

        test_db = DatabaseManager(str(tmp_path / "test.db"))
        monkeypatch.setattr(db_module, "db", test_db)
        monkeypatch.setattr(slp_module, "db", test_db)

        log_file = tmp_path / "auth.log"
        log_file.write_text(
            "Apr 19 10:00:01 server sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
        )

        slp_module.parse_auth_log(agent_id="test-agent", log_path=str(log_file))

        norm_logs = test_db.get_normalized_logs(event_type="ssh_failure")
        assert len(norm_logs) >= 1
        assert norm_logs[0].src_ip == "1.2.3.4"
        assert norm_logs[0].event_type == "ssh_failure"

    def test_ssh_success_writes_to_normalized_logs(self, tmp_path, monkeypatch):
        import server.database as db_module
        import server.security_log_parser as slp_module

        test_db = DatabaseManager(str(tmp_path / "test.db"))
        monkeypatch.setattr(db_module, "db", test_db)
        monkeypatch.setattr(slp_module, "db", test_db)

        log_file = tmp_path / "auth.log"
        log_file.write_text(
            "Apr 19 10:05:00 server sshd[1234]: Accepted password for mehmet from 192.168.1.5 port 22 ssh2\n"
        )

        slp_module.parse_auth_log(agent_id="test-agent", log_path=str(log_file))

        norm_logs = test_db.get_normalized_logs(event_type="ssh_success")
        assert len(norm_logs) >= 1
        assert norm_logs[0].src_ip == "192.168.1.5"

    def test_multiple_ssh_failures_enable_brute_force_rule(self, tmp_path, monkeypatch):
        import server.database as db_module
        import server.correlator as corr_module
        import server.security_log_parser as slp_module

        test_db = DatabaseManager(str(tmp_path / "test.db"))
        monkeypatch.setattr(db_module, "db", test_db)
        monkeypatch.setattr(corr_module, "db", test_db)
        monkeypatch.setattr(slp_module, "db", test_db)

        now = datetime.now(timezone.utc)
        lines = "\n".join(
            (now - timedelta(seconds=i)).strftime("%b %d %H:%M:%S")
            + " server sshd[1234]: Failed password for root from 5.5.5.5 port 22 ssh2"
            for i in range(5)
        )
        log_file = tmp_path / "auth.log"
        log_file.write_text(lines + "\n")

        slp_module.parse_auth_log(agent_id="test-agent", log_path=str(log_file))

        norm_logs = test_db.get_normalized_logs(event_type="ssh_failure")
        assert len(norm_logs) >= 5

        c = Correlator(rules_path=str(tmp_path / "empty.json"))
        c._rules = [_make_rule(
            match_event_type="ssh_failure", threshold=5,
            output_event_type="brute_force_detected",
        )]
        events = c.run()
        assert len(events) == 1
        assert events[0].group_value == "5.5.5.5"
