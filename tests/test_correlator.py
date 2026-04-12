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
    event_type: str,
    src_ip: str = "10.0.0.1",
    source_host: str = "sensor1",
    severity: str = "warning",
    minutes_ago: int = 0,
) -> NormalizedLog:
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return NormalizedLog(
        log_id      = str(uuid.uuid4()),
        raw_id      = str(uuid.uuid4()),
        source_type = LogSourceType.AUTH_LOG,
        source_host = source_host,
        timestamp   = ts,
        severity    = severity,
        category    = LogCategory.AUTHENTICATION,
        event_type  = event_type,
        src_ip      = src_ip,
        message     = f"Test log: {event_type}",
    )


def _store_logs(test_db: DatabaseManager, logs: list[NormalizedLog]) -> None:
    for log in logs:
        test_db.save_normalized_log(log)


def _make_rule(
    rule_id: str = "test_rule",
    match_event_type: str = "ssh_failure",
    group_by: str = "src_ip",
    window_seconds: int = 300,
    threshold: int = 5,
    severity: str = "critical",
    output_event_type: str = "brute_force_detected",
    match_severity: str = None,
) -> CorrelationRule:
    return CorrelationRule(
        rule_id          = rule_id,
        name             = "Test Kuralı",
        description      = "Test",
        match_event_type = match_event_type,
        group_by         = group_by,
        window_seconds   = window_seconds,
        threshold        = threshold,
        severity         = severity,
        output_event_type= output_event_type,
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
                "match_event_type": "ssh_failure", "group_by": "src_ip",
                "window_seconds": 300, "threshold": 5,
                "severity": "critical", "output_event_type": "brute_force",
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
                "match_event_type": "ssh_failure", "group_by": "src_ip",
                "window_seconds": 60, "threshold": 3,
                "severity": "warning", "output_event_type": "test",
                "enabled": True,
            },
            {
                "rule_id": "r2", "name": "Disabled", "description": "",
                "match_event_type": "ssh_failure", "group_by": "src_ip",
                "window_seconds": 60, "threshold": 3,
                "severity": "warning", "output_event_type": "test",
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
                "match_event_type": "ssh_failure", "group_by": "src_ip",
                "window_seconds": 60, "threshold": 3,
                "severity": "warning", "output_event_type": "test",
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
    def setup(self, tmp_path, monkeypatch):
        """Geçici DB ve boş kural listesiyle Correlator oluştur."""
        import server.database as db_module
        test_db = DatabaseManager(str(tmp_path / "test.db"))
        monkeypatch.setattr(db_module, "db", test_db)

        import server.correlator as corr_module
        monkeypatch.setattr(corr_module, "db", test_db)

        c = Correlator(rules_path=str(tmp_path / "empty.json"))
        c._rules = []   # başlangıçta kural yok
        return c, test_db

    def test_no_events_when_below_threshold(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=5)
        correlator._rules = [rule]

        # 4 log ekle (eşik 5)
        logs = [_make_normalized_log("ssh_failure", src_ip="1.2.3.4") for _ in range(4)]
        _store_logs(test_db, logs)

        events = correlator.run()
        assert len(events) == 0

    def test_event_produced_when_threshold_reached(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=5)
        correlator._rules = [rule]

        # 5 log ekle (eşiğe tam ulaşır)
        logs = [_make_normalized_log("ssh_failure", src_ip="1.2.3.4") for _ in range(5)]
        _store_logs(test_db, logs)

        events = correlator.run()
        assert len(events) == 1
        assert events[0].event_type == "brute_force_detected"
        assert events[0].group_value == "1.2.3.4"
        assert events[0].matched_count == 5

    def test_different_ips_tracked_separately(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=3)
        correlator._rules = [rule]

        # İki farklı IP'den 3'er log
        for ip in ["1.1.1.1", "2.2.2.2"]:
            logs = [_make_normalized_log("ssh_failure", src_ip=ip) for _ in range(3)]
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
        fresh = [_make_normalized_log("ssh_failure", src_ip="1.2.3.4", minutes_ago=0) for _ in range(2)]
        old   = [_make_normalized_log("ssh_failure", src_ip="1.2.3.4", minutes_ago=5) for _ in range(2)]
        _store_logs(test_db, fresh + old)

        events = correlator.run()
        # Toplam 4 log var ama 2'si pencere dışı — eşik 3'e ulaşmaz
        assert len(events) == 0

    def test_duplicate_event_not_saved_twice(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=3)
        correlator._rules = [rule]

        logs = [_make_normalized_log("ssh_failure", src_ip="1.2.3.4") for _ in range(5)]
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
        warn_logs = [_make_normalized_log("ssh_failure", src_ip="1.2.3.4", severity="warning") for _ in range(3)]
        crit_logs = [_make_normalized_log("ssh_failure", src_ip="1.2.3.4", severity="critical") for _ in range(3)]
        _store_logs(test_db, warn_logs + crit_logs)

        events = correlator.run()
        assert len(events) == 1
        assert events[0].matched_count == 3   # sadece critical'lar sayıldı

    def test_event_type_prefix_match(self, setup):
        """match_event_type prefix ile farklı wazuh kurallarını yakalar."""
        correlator, test_db = setup
        rule = _make_rule(
            match_event_type="wazuh_rule_",
            group_by="source_host",
            threshold=3,
            output_event_type="wazuh_burst",
        )
        correlator._rules = [rule]

        logs = [
            _make_normalized_log("wazuh_rule_5501", source_host="web01"),
            _make_normalized_log("wazuh_rule_5502", source_host="web01"),
            _make_normalized_log("wazuh_rule_1001", source_host="web01"),
        ]
        _store_logs(test_db, logs)

        events = correlator.run()
        assert len(events) == 1
        assert events[0].group_value == "web01"

    def test_correlated_event_saved_to_db(self, setup):
        correlator, test_db = setup
        rule = _make_rule(threshold=3)
        correlator._rules = [rule]

        logs = [_make_normalized_log("ssh_failure", src_ip="1.2.3.4") for _ in range(3)]
        _store_logs(test_db, logs)

        correlator.run()

        db_events = test_db.get_correlated_events()
        assert len(db_events) == 1
        assert db_events[0].rule_id == "test_rule"
        assert db_events[0].severity == "critical"
