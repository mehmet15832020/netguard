"""
Tests — SQLite database katmanı ve güvenlik modülleri
"""

import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

import pytest

# Test için geçici DB dosyası kullan
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["NETGUARD_DB_PATH"] = _tmp.name
_tmp.close()

from server.database import DatabaseManager
from server.security_log_parser import _parse_log_date, _RE_FAILED, _RE_ACCEPTED, _RE_SUDO
from server.port_monitor import PortMonitor
from server.config_monitor import ConfigMonitor
from shared.models import (
    Alert, AlertSeverity, AlertStatus,
    SecurityEvent, SecurityEventType,
)


@pytest.fixture
def db_manager():
    """Her test için taze bir geçici veritabanı."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    manager = DatabaseManager(db_path=path)
    yield manager
    os.unlink(path)


def _make_alert(**kwargs) -> Alert:
    defaults = dict(
        alert_id    = str(uuid.uuid4()),
        agent_id    = "agent-test",
        hostname    = "testhost",
        severity    = AlertSeverity.WARNING,
        status      = AlertStatus.ACTIVE,
        metric      = "cpu",
        message     = "CPU yüksek",
        value       = 85.0,
        threshold   = 80.0,
        triggered_at= datetime.now(timezone.utc),
    )
    defaults.update(kwargs)
    return Alert(**defaults)


def _make_event(**kwargs) -> SecurityEvent:
    defaults = dict(
        event_id    = str(uuid.uuid4()),
        agent_id    = "agent-test",
        hostname    = "testhost",
        event_type  = SecurityEventType.SSH_FAILURE,
        severity    = "warning",
        source_ip   = "10.0.0.1",
        username    = "root",
        message     = "Başarısız giriş",
        occurred_at = datetime.now(timezone.utc),
    )
    defaults.update(kwargs)
    return SecurityEvent(**defaults)


# ------------------------------------------------------------------ #
#  Alert CRUD
# ------------------------------------------------------------------ #

class TestAlerts:
    def test_save_and_retrieve(self, db_manager):
        alert = _make_alert()
        db_manager.save_alert(alert)
        results = db_manager.get_alerts()
        assert len(results) == 1
        assert results[0].alert_id == alert.alert_id

    def test_filter_by_status(self, db_manager):
        active = _make_alert(status=AlertStatus.ACTIVE)
        resolved = _make_alert(status=AlertStatus.RESOLVED,
                               resolved_at=datetime.now(timezone.utc))
        db_manager.save_alert(active)
        db_manager.save_alert(resolved)

        assert len(db_manager.get_alerts(status="active")) == 1
        assert len(db_manager.get_alerts(status="resolved")) == 1
        assert len(db_manager.get_alerts()) == 2

    def test_resolve_existing_alert(self, db_manager):
        alert = _make_alert()
        db_manager.save_alert(alert)

        # Aynı alert_id ile resolved olarak tekrar kaydet
        resolved = _make_alert(
            alert_id   = alert.alert_id,
            status     = AlertStatus.RESOLVED,
            resolved_at= datetime.now(timezone.utc),
        )
        db_manager.save_alert(resolved)

        results = db_manager.get_alerts()
        assert len(results) == 1
        assert results[0].status == AlertStatus.RESOLVED

    def test_limit(self, db_manager):
        for _ in range(10):
            db_manager.save_alert(_make_alert())
        assert len(db_manager.get_alerts(limit=5)) == 5

    def test_severity_preserved(self, db_manager):
        alert = _make_alert(severity=AlertSeverity.CRITICAL)
        db_manager.save_alert(alert)
        result = db_manager.get_alerts()[0]
        assert result.severity == AlertSeverity.CRITICAL


# ------------------------------------------------------------------ #
#  SecurityEvent CRUD
# ------------------------------------------------------------------ #

class TestSecurityEvents:
    def test_save_and_retrieve(self, db_manager):
        event = _make_event()
        db_manager.save_security_event(event)
        results = db_manager.get_security_events()
        assert len(results) == 1
        assert results[0].event_id == event.event_id

    def test_duplicate_ignored(self, db_manager):
        event = _make_event()
        db_manager.save_security_event(event)
        db_manager.save_security_event(event)  # aynı event_id
        assert len(db_manager.get_security_events()) == 1

    def test_filter_by_type(self, db_manager):
        db_manager.save_security_event(_make_event(event_type=SecurityEventType.SSH_FAILURE))
        db_manager.save_security_event(_make_event(event_type=SecurityEventType.SUDO_USAGE))

        failures = db_manager.get_security_events(event_type="ssh_failure")
        assert len(failures) == 1

    def test_filter_by_ip(self, db_manager):
        db_manager.save_security_event(_make_event(source_ip="1.1.1.1"))
        db_manager.save_security_event(_make_event(source_ip="2.2.2.2"))

        results = db_manager.get_security_events(source_ip="1.1.1.1")
        assert len(results) == 1
        assert results[0].source_ip == "1.1.1.1"

    def test_count_recent_failures(self, db_manager):
        ip = "10.0.0.99"
        now = datetime.now(timezone.utc)
        since = (now - timedelta(minutes=5)).isoformat()

        for _ in range(3):
            db_manager.save_security_event(_make_event(source_ip=ip))

        count = db_manager.count_recent_failures(ip, since)
        assert count == 3

    def test_count_failures_old_excluded(self, db_manager):
        ip = "10.0.0.88"
        old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        db_manager.save_security_event(_make_event(source_ip=ip, occurred_at=old_time))

        since = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        count = db_manager.count_recent_failures(ip, since)
        assert count == 0


# ------------------------------------------------------------------ #
#  Log Parser — Regex
# ------------------------------------------------------------------ #

class TestLogParserRegex:
    def test_failed_password(self):
        line = "Apr  8 14:23:01 server sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2"
        m = _RE_FAILED.search(line)
        assert m is not None
        assert m.group(1) == "root"
        assert m.group(2) == "192.168.1.5"

    def test_failed_invalid_user(self):
        line = "Apr  8 14:23:01 server sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2"
        m = _RE_FAILED.search(line)
        assert m is not None
        assert m.group(1) == "admin"
        assert m.group(2) == "10.0.0.1"

    def test_accepted_password(self):
        line = "Apr  8 14:25:00 server sshd[5678]: Accepted password for mehmet from 192.168.1.10 port 22 ssh2"
        m = _RE_ACCEPTED.search(line)
        assert m is not None
        assert m.group(1) == "mehmet"
        assert m.group(2) == "192.168.1.10"

    def test_sudo_usage(self):
        line = "Apr  8 14:30:00 server sudo: mehmet : TTY=pts/0 ; PWD=/home/mehmet ; USER=root ; COMMAND=/bin/bash"
        m = _RE_SUDO.search(line)
        assert m is not None
        assert m.group(1) == "mehmet"
        assert "/bin/bash" in m.group(2)

    def test_parse_log_date(self):
        dt = _parse_log_date("Apr  8 14:23:01")
        assert dt.month == 4
        assert dt.day == 8
        assert dt.hour == 14


# ------------------------------------------------------------------ #
#  Port Monitor
# ------------------------------------------------------------------ #

class TestPortMonitor:
    def test_first_call_returns_empty(self, monkeypatch):
        monkeypatch.setattr(
            "server.port_monitor._get_listening_ports",
            lambda: {("0.0.0.0", 8080)}
        )
        pm = PortMonitor()
        events = pm.check("agent-1")
        assert events == []  # Baseline — olay yok

    def test_new_port_detected(self, monkeypatch, db_manager, monkeypatch_db):
        calls = [
            {("0.0.0.0", 8080)},
            {("0.0.0.0", 8080), ("0.0.0.0", 9999)},  # 9999 yeni açıldı
        ]
        call_iter = iter(calls)
        monkeypatch.setattr(
            "server.port_monitor._get_listening_ports",
            lambda: next(call_iter)
        )
        pm = PortMonitor()
        pm.check("agent-1")  # baseline
        events = pm.check("agent-1")
        assert len(events) == 1
        assert events[0].event_type == SecurityEventType.PORT_OPENED
        assert "9999" in events[0].message

    def test_closed_port_detected(self, monkeypatch, monkeypatch_db):
        calls = [
            {("0.0.0.0", 8080), ("0.0.0.0", 22)},
            {("0.0.0.0", 8080)},  # 22 kapandı
        ]
        call_iter = iter(calls)
        monkeypatch.setattr(
            "server.port_monitor._get_listening_ports",
            lambda: next(call_iter)
        )
        pm = PortMonitor()
        pm.check("agent-1")
        events = pm.check("agent-1")
        assert len(events) == 1
        assert events[0].event_type == SecurityEventType.PORT_CLOSED


# ------------------------------------------------------------------ #
#  Config Monitor
# ------------------------------------------------------------------ #

class TestConfigMonitor:
    def test_baseline_no_events(self, tmp_path):
        watched = tmp_path / "test.conf"
        watched.write_text("initial content")
        os.environ["WATCHED_FILES"] = str(watched)
        cm = ConfigMonitor()
        events = cm.check("agent-1")
        assert events == []  # Baseline

    def test_change_detected(self, tmp_path):
        watched = tmp_path / "test.conf"
        watched.write_text("initial content")
        os.environ["WATCHED_FILES"] = str(watched)
        cm = ConfigMonitor()
        cm.check("agent-1")  # baseline

        watched.write_text("modified content")
        events = cm.check("agent-1")
        assert len(events) == 1
        assert events[0].event_type == SecurityEventType.CHECKSUM_CHANGED

    def test_no_change_no_event(self, tmp_path):
        watched = tmp_path / "test.conf"
        watched.write_text("same content")
        os.environ["WATCHED_FILES"] = str(watched)
        cm = ConfigMonitor()
        cm.check("agent-1")
        events = cm.check("agent-1")
        assert events == []


@pytest.fixture
def monkeypatch_db(monkeypatch, db_manager):
    """Port/config testleri için db.save_security_event'i mock'la."""
    monkeypatch.setattr("server.port_monitor.db", db_manager)
    monkeypatch.setattr("server.config_monitor.db", db_manager)
