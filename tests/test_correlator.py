"""
NetGuard — Korelasyon motoru testleri

Gerçek DB'ye geçici dosya ile yazar, mock kullanılmaz.
"""

import json
import pytest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from server.database import DatabaseManager
from server.correlator import Correlator, CorrelationRule
from shared.models import NormalizedLog, LogSourceType, LogCategory


# ------------------------------------------------------------------ #
#  Yardımcı fonksiyonlar
# ------------------------------------------------------------------ #

def _make_normalized_log(
    event_action: str,
    source_ip: str = "10.0.0.1",
    observer_hostname: str = "sensor1",
    severity: str = "warning",
    minutes_ago: int = 0,
) -> NormalizedLog:
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return NormalizedLog(
        log_id      = str(uuid.uuid4()),
        raw_id      = str(uuid.uuid4()),
        source_type = LogSourceType.AUTH_LOG,
        observer_hostname = observer_hostname,
        timestamp   = ts,
        severity    = severity,
        event_category    = LogCategory.AUTHENTICATION,
        event_action  = event_action,
        source_ip      = source_ip,
        message     = f"Test log: {event_action}",
    )


def _store_logs(test_db: DatabaseManager, logs: list[NormalizedLog]) -> None:
    for log in logs:
        test_db.save_normalized_log(log)


def _make_rule(
    rule_id: str = "test_rule",
    match_event_action: str = "ssh_failure",
    group_by: str = "source_ip",
    window_seconds: int = 300,
    threshold: int = 5,
    severity: str = "critical",
    output_event_action: str = "brute_force_detected",
    match_severity: str = None,
) -> CorrelationRule:
    return CorrelationRule(
        rule_id          = rule_id,
        name             = "Test Kuralı",
        description      = "Test",
        match_event_action = match_event_action,
        group_by         = group_by,
        window_seconds   = window_seconds,
        threshold        = threshold,
        severity         = severity,
        output_event_action= output_event_action,
        enabled          = True,
        match_severity   = match_severity,
    )


# ------------------------------------------------------------------ #
#  Kural yükleme testleri
# ------------------------------------------------------------------ #

class TestRuleLoading:
    def test_loads_rules_from_json(self, tmp_path):
        rules_file = tmp_path / "rules.json"
        rules_file.write_text(json.dumps([
            {
                "rule_id": "r1", "name": "Rule 1", "description": "",
                "match_event_action": "ssh_failure", "group_by": "source_ip",
                "window_seconds": 300, "threshold": 5,
                "severity": "critical", "output_event_action": "brute_force",
                "enabled": True,
            }
        ]))
        c = Correlator(rules_path=str(rules_file))
        assert len(c.rules) == 1
        assert c.rules[0].rule_id == "r1"

    def test_disabled_rules_skipped(self, tmp_path):
        rules_file = tmp_path / "rules.json"
        rules_file.write_text(json.dumps([
            {
                "rule_id": "r1", "name": "Active", "description": "",
                "match_event_action": "ssh_failure", "group_by": "source_ip",
                "window_seconds": 60, "threshold": 3,
                "severity": "warning", "output_event_action": "test",
                "enabled": True,
            },
            {
                "rule_id": "r2", "name": "Disabled", "description": "",
                "match_event_action": "ssh_failure", "group_by": "source_ip",
                "window_seconds": 60, "threshold": 3,
                "severity": "warning", "output_event_action": "test",
                "enabled": False,
            },
        ]))
        c = Correlator(rules_path=str(rules_file))
        assert len(c.rules) == 1
        assert c.rules[0].rule_id == "r1"

    def test_missing_file_returns_zero(self, tmp_path):
        c = Correlator(rules_path=str(tmp_path / "missing.json"))
        assert len(c.rules) == 0

    def test_reload_updates_rules(self, tmp_path):
        rules_file = tmp_path / "rules.json"
        rules_file.write_text(json.dumps([]))
        c = Correlator(rules_path=str(rules_file))
        assert len(c.rules) == 0

        rules_file.write_text(json.dumps([
            {
                "rule_id": "new_rule", "name": "New", "description": "",
                "match_event_action": "ssh_failure", "group_by": "source_ip",
                "window_seconds": 60, "threshold": 3,
                "severity": "warning", "output_event_action": "test",
                "enabled": True,
            }
        ]))
        c.load_rules()
        assert len(c.rules) == 1


# ------------------------------------------------------------------ #
#  Korelasyon çalıştırma testleri
# ------------------------------------------------------------------ #

class TestCorrelatorRun:
    @pytest.fixture
    def setup(self, tmp_db, tmp_path, monkeypatch):
        """Geçici DB ve boş kural listesiyle Correlator oluştur."""
        import server.correlator as corr_module
        monkeypatch.setattr(corr_module, "db", tmp_db)

        empty_v2_dir = str(tmp_path / "no_sigma_v2")
        c = Correlator(rules_path=str(tmp_path / "empty.json"), sigma_v2_dir=empty_v2_dir)
        c._rules = []
        return c, tmp_db

    def test_no_events_when_below_threshold(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=5)
        correlator._rules = [rule]

        # 4 log ekle (eşik 5)
        logs = [_make_normalized_log("ssh_failure", source_ip="1.2.3.4") for _ in range(4)]
        _store_logs(test_db, logs)

        events = correlator.run()
        assert len(events) == 0

    def test_event_produced_when_threshold_reached(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=5)
        correlator._rules = [rule]

        # 5 log ekle (eşiğe tam ulaşır)
        logs = [_make_normalized_log("ssh_failure", source_ip="1.2.3.4") for _ in range(5)]
        _store_logs(test_db, logs)

        events = correlator.run()
        assert len(events) == 1
        assert events[0].event_action == "brute_force_detected"
        assert events[0].group_value == "1.2.3.4"
        assert events[0].matched_count == 5

    def test_different_ips_tracked_separately(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=3)
        correlator._rules = [rule]

        # İki farklı IP'den 3'er log
        for ip in ["1.1.1.1", "2.2.2.2"]:
            logs = [_make_normalized_log("ssh_failure", source_ip=ip) for _ in range(3)]
            _store_logs(test_db, logs)

        events = correlator.run()
        assert len(events) == 2
        group_values = {e.group_value for e in events}
        assert "1.1.1.1" in group_values
        assert "2.2.2.2" in group_values

    def test_logs_outside_window_not_counted(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=3, window_seconds=60)
        correlator._rules = [rule]

        # 2 taze log + 2 eski log (pencere dışı)
        fresh = [_make_normalized_log("ssh_failure", source_ip="1.2.3.4", minutes_ago=0) for _ in range(2)]
        old   = [_make_normalized_log("ssh_failure", source_ip="1.2.3.4", minutes_ago=5) for _ in range(2)]
        _store_logs(test_db, fresh + old)

        events = correlator.run()
        # Toplam 4 log var ama 2'si pencere dışı — eşik 3'e ulaşmaz
        assert len(events) == 0

    def test_duplicate_event_not_saved_twice(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=3)
        correlator._rules = [rule]

        logs = [_make_normalized_log("ssh_failure", source_ip="1.2.3.4") for _ in range(5)]
        _store_logs(test_db, logs)

        events1 = correlator.run()
        events2 = correlator.run()  # aynı pencere içinde tekrar çalıştır

        assert len(events1) == 1
        assert len(events2) == 0   # duplicate önlendi

    def test_severity_filter_applied(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=3, match_severity="critical")
        correlator._rules = [rule]

        # 3 warning + 3 critical log
        warn_logs = [_make_normalized_log("ssh_failure", source_ip="1.2.3.4", severity="warning") for _ in range(3)]
        crit_logs = [_make_normalized_log("ssh_failure", source_ip="1.2.3.4", severity="critical") for _ in range(3)]
        _store_logs(test_db, warn_logs + crit_logs)

        events = correlator.run()
        assert len(events) == 1
        assert events[0].matched_count == 3   # sadece critical'lar sayıldı

    def test_event_type_prefix_match(self, setup):
        """match_event_action prefix ile farklı wazuh kurallarını yakalar."""
        correlator, test_db = setup
        rule = _make_rule(
            match_event_action="wazuh_rule_",
            group_by="observer_hostname",
            threshold=3,
            output_event_action="wazuh_burst",
        )
        correlator._rules = [rule]

        logs = [
            _make_normalized_log("wazuh_rule_5501", observer_hostname="web01"),
            _make_normalized_log("wazuh_rule_5502", observer_hostname="web01"),
            _make_normalized_log("wazuh_rule_1001", observer_hostname="web01"),
        ]
        _store_logs(test_db, logs)

        events = correlator.run()
        assert len(events) == 1
        assert events[0].group_value == "web01"

    def test_correlated_event_saved_to_db(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=3)
        correlator._rules = [rule]

        logs = [_make_normalized_log("ssh_failure", source_ip="1.2.3.4") for _ in range(3)]
        _store_logs(test_db, logs)

        correlator.run()

        db_events = test_db.get_correlated_events()
        assert len(db_events) == 1
        assert db_events[0].rule_id == "test_rule"
        assert db_events[0].severity == "critical"


# ------------------------------------------------------------------ #
#  Threat Intel Escalation testleri
# ------------------------------------------------------------------ #

class TestThreatIntelEscalation:
    @pytest.fixture
    def setup(self, tmp_db, tmp_path, monkeypatch):
        import server.correlator as corr_module
        monkeypatch.setattr(corr_module, "db", tmp_db)
        c = Correlator(rules_path=str(tmp_path / "empty.json"), sigma_v2_dir=str(tmp_path / "no_sigma_v2"))
        c._rules = []
        return c, tmp_db

    def test_high_ti_score_escalates_to_critical(self, setup, monkeypatch):
        correlator, test_db = setup
        rule = _make_rule(threshold=3, severity="warning")
        correlator._rules = [rule]

        logs = [_make_normalized_log("ssh_failure", source_ip="1.2.3.4") for _ in range(3)]
        _store_logs(test_db, logs)

        import server.threat_intel as ti_module
        monkeypatch.setattr(ti_module, "lookup", lambda ip: {"score": 85})

        correlator.run()

        incidents = test_db.get_incidents()
        assert len(incidents) == 1
        assert incidents[0]["severity"] == "critical"

    def test_low_ti_score_no_escalation(self, setup, monkeypatch):
        correlator, test_db = setup
        rule = _make_rule(threshold=3, severity="warning")
        correlator._rules = [rule]

        logs = [_make_normalized_log("ssh_failure", source_ip="1.2.3.4") for _ in range(3)]
        _store_logs(test_db, logs)

        import server.threat_intel as ti_module
        monkeypatch.setattr(ti_module, "lookup", lambda ip: {"score": 30})

        correlator.run()

        incidents = test_db.get_incidents()
        assert len(incidents) == 1
        assert incidents[0]["severity"] == "warning"

    def test_no_ti_result_no_escalation(self, setup, monkeypatch):
        correlator, test_db = setup
        rule = _make_rule(threshold=3, severity="warning")
        correlator._rules = [rule]

        logs = [_make_normalized_log("ssh_failure", source_ip="10.0.0.1") for _ in range(3)]
        _store_logs(test_db, logs)

        import server.threat_intel as ti_module
        monkeypatch.setattr(ti_module, "lookup", lambda ip: None)

        correlator.run()

        incidents = test_db.get_incidents()
        assert len(incidents) == 1
        assert incidents[0]["severity"] == "warning"


# ------------------------------------------------------------------ #
#  Cross-source (distinct source_type) korelasyon testleri
# ------------------------------------------------------------------ #

class TestCrossSourceCorrelation:
    @pytest.fixture
    def setup(self, tmp_db, tmp_path, monkeypatch):
        import server.correlator as corr_module
        monkeypatch.setattr(corr_module, "db", tmp_db)
        c = Correlator(rules_path=str(tmp_path / "empty.json"), sigma_v2_dir=str(tmp_path / "no_sigma_v2"))
        c._rules = []
        return c, tmp_db

    def _cross_source_rule(self):
        from server.correlator import CorrelationRule
        return CorrelationRule(
            rule_id          = "multi_source_attack",
            name             = "Çok Kaynaklı Saldırı",
            description      = "Test",
            match_event_action = "",
            group_by         = "source_ip",
            window_seconds   = 300,
            threshold        = 2,
            severity         = "critical",
            output_event_action= "multi_source_attack_detected",
            enabled          = True,
            distinct_by      = "source_type",
        )

    def test_fires_when_ip_in_two_source_types(self, setup, monkeypatch):
        correlator, test_db = setup
        correlator._rules = [self._cross_source_rule()]

        import server.threat_intel as ti_module
        monkeypatch.setattr(ti_module, "lookup", lambda ip: None)

        # Aynı source_ip, farklı source_type
        log1 = _make_normalized_log("port_scan_attempt", source_ip="1.2.3.4")
        log1 = log1.model_copy(update={"source_type": LogSourceType.NETGUARD})
        log2 = _make_normalized_log("ssh_failure", source_ip="1.2.3.4")
        # log2 varsayılan AUTH_LOG source_type'ı kullanır
        _store_logs(test_db, [log1, log2])

        events = correlator.run()
        assert len(events) == 1
        assert events[0].event_action == "multi_source_attack_detected"
        assert events[0].group_value == "1.2.3.4"

    def test_no_fire_when_single_source_type(self, setup, monkeypatch):
        correlator, test_db = setup
        correlator._rules = [self._cross_source_rule()]

        import server.threat_intel as ti_module
        monkeypatch.setattr(ti_module, "lookup", lambda ip: None)

        # Aynı source_ip, aynı source_type (AUTH_LOG)
        logs = [_make_normalized_log("ssh_failure", source_ip="1.2.3.4") for _ in range(5)]
        _store_logs(test_db, logs)

        events = correlator.run()
        assert len(events) == 0

    def test_different_ips_tracked_separately(self, setup, monkeypatch):
        correlator, test_db = setup
        correlator._rules = [self._cross_source_rule()]

        import server.threat_intel as ti_module
        monkeypatch.setattr(ti_module, "lookup", lambda ip: None)

        # 1.2.3.4: 2 farklı source_type → tetiklenmeli
        log_a = _make_normalized_log("port_scan_attempt", source_ip="1.2.3.4")
        log_a = log_a.model_copy(update={"source_type": LogSourceType.NETGUARD})
        log_b = _make_normalized_log("ssh_failure", source_ip="1.2.3.4")
        # 5.6.7.8: tek source_type → tetiklenmemeli
        log_c = _make_normalized_log("ssh_failure", source_ip="5.6.7.8")
        _store_logs(test_db, [log_a, log_b, log_c])

        events = correlator.run()
        assert len(events) == 1
        assert events[0].group_value == "1.2.3.4"
