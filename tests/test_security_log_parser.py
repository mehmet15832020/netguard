"""
NetGuard — security_log_parser birim testleri

auth.log dosyasını mock'layarak parse_auth_log() fonksiyonunu test eder.
Hydra SSH brute force saldırısı senaryosunu simüle eder.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call
from pathlib import Path

from shared.models import SecurityEventType


# ------------------------------------------------------------------ #
#  Yardımcılar
# ------------------------------------------------------------------ #

def _make_failed_line(user: str, ip: str, date: str = "Apr 16 10:00:00") -> str:
    return f"{date} server sshd[1234]: Failed password for {user} from {ip} port 54321 ssh2\n"

def _make_invalid_user_line(user: str, ip: str, date: str = "Apr 16 10:00:00") -> str:
    return f"{date} server sshd[1234]: Failed password for invalid user {user} from {ip} port 54321 ssh2\n"

def _make_accepted_line(user: str, ip: str, date: str = "Apr 16 10:01:00") -> str:
    return f"{date} server sshd[1234]: Accepted password for {user} from {ip} port 54321 ssh2\n"

def _make_publickey_line(user: str, ip: str, date: str = "Apr 16 10:01:00") -> str:
    return f"{date} server sshd[1234]: Accepted publickey for {user} from {ip} port 54321 ssh2\n"

def _make_sudo_line(user: str, command: str = "/bin/bash", date: str = "Apr 16 10:02:00") -> str:
    return f"{date} server sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}\n"


# ------------------------------------------------------------------ #
#  parse_auth_log testleri
# ------------------------------------------------------------------ #

class TestParseAuthLog:
    """parse_auth_log() fonksiyonunu farklı senaryolarla test eder."""

    def _run(self, lines: list[str], mock_db=None, count_recent=0):
        """
        Yardımcı: verilen satırlarla parse_auth_log çalıştırır.
        mock_db: db modülünü mock'lar; count_recent: brute force sorgu dönüş değeri.
        """
        import server.security_log_parser as parser_module

        # db'yi mock'la
        db_mock = MagicMock()
        db_mock.count_recent_failures.return_value = count_recent

        with patch.object(parser_module, "db", db_mock):
            # _tail fonksiyonunu mock'la (dosyayı okumadan satırları enjekte et)
            with patch.object(parser_module, "_tail", return_value=lines):
                # Dosya varlık kontrolü için Path.exists() mock'la
                with patch("pathlib.Path.exists", return_value=True):
                    events = parser_module.parse_auth_log(
                        agent_id="test-agent",
                        log_path="/fake/auth.log",
                    )
        return events, db_mock

    # --- Temel tespitler ---

    def test_failed_ssh_detected(self):
        lines = [_make_failed_line("root", "192.168.1.100")]
        events, _ = self._run(lines)
        ssh_failures = [e for e in events if e.event_type == SecurityEventType.SSH_FAILURE]
        assert len(ssh_failures) == 1
        assert ssh_failures[0].source_ip == "192.168.1.100"
        assert ssh_failures[0].username == "root"
        assert ssh_failures[0].severity == "warning"

    def test_invalid_user_ssh_detected(self):
        """'invalid user' ifadesi içeren satır da tespit edilmeli."""
        lines = [_make_invalid_user_line("hacker", "10.0.0.5")]
        events, _ = self._run(lines)
        ssh_failures = [e for e in events if e.event_type == SecurityEventType.SSH_FAILURE]
        assert len(ssh_failures) == 1
        assert ssh_failures[0].username == "hacker"
        assert ssh_failures[0].source_ip == "10.0.0.5"

    def test_accepted_password_detected(self):
        lines = [_make_accepted_line("mehmet", "192.168.1.50")]
        events, _ = self._run(lines)
        successes = [e for e in events if e.event_type == SecurityEventType.SSH_SUCCESS]
        assert len(successes) == 1
        assert successes[0].source_ip == "192.168.1.50"
        assert successes[0].username == "mehmet"
        assert successes[0].severity == "info"

    def test_accepted_publickey_detected(self):
        lines = [_make_publickey_line("admin", "192.168.1.51")]
        events, _ = self._run(lines)
        successes = [e for e in events if e.event_type == SecurityEventType.SSH_SUCCESS]
        assert len(successes) == 1
        assert successes[0].username == "admin"

    def test_sudo_usage_detected(self):
        lines = [_make_sudo_line("mehmet", "/usr/bin/apt")]
        events, _ = self._run(lines)
        sudo_events = [e for e in events if e.event_type == SecurityEventType.SUDO_USAGE]
        assert len(sudo_events) == 1
        assert sudo_events[0].username == "mehmet"
        assert sudo_events[0].severity == "warning"
        assert "/usr/bin/apt" in sudo_events[0].message

    def test_irrelevant_lines_ignored(self):
        lines = [
            "Apr 16 10:00:00 server systemd[1]: Started session.\n",
            "Apr 16 10:00:01 server cron[999]: some cron job\n",
        ]
        events, _ = self._run(lines)
        assert len(events) == 0

    def test_empty_file_returns_empty(self):
        events, _ = self._run([])
        assert events == []

    def test_file_not_found_returns_empty(self):
        import server.security_log_parser as parser_module
        with patch("pathlib.Path.exists", return_value=False):
            events = parser_module.parse_auth_log("agent-1", log_path="/no/such/file")
        assert events == []

    # --- Brute force tespiti ---

    def test_brute_force_triggered_when_threshold_reached(self):
        """
        Hydra senaryosu: aynı IP'den 5 başarısız giriş → brute force alarmı.
        count_recent_failures eşiği (5) döndürünce BRUTE_FORCE eventi üretilmeli.
        """
        lines = [_make_failed_line("root", "10.10.10.10")]
        # DB'den 5 kayıt geldiğini simüle et (eşik = 5)
        events, _ = self._run(lines, count_recent=5)
        brute_force_events = [e for e in events if e.event_type == SecurityEventType.BRUTE_FORCE]
        assert len(brute_force_events) == 1
        assert brute_force_events[0].severity == "critical"
        assert "10.10.10.10" in brute_force_events[0].message

    def test_brute_force_not_triggered_below_threshold(self):
        """4 başarısız giriş — eşik aşılmadı, brute force alarmı olmamalı."""
        lines = [_make_failed_line("root", "10.10.10.11")]
        events, _ = self._run(lines, count_recent=4)
        brute_force_events = [e for e in events if e.event_type == SecurityEventType.BRUTE_FORCE]
        assert len(brute_force_events) == 0

    def test_brute_force_message_includes_count(self):
        """Brute force mesajı kaç başarısız giriş olduğunu içermeli."""
        lines = [_make_failed_line("admin", "172.16.0.1")]
        events, _ = self._run(lines, count_recent=10)
        bf_events = [e for e in events if e.event_type == SecurityEventType.BRUTE_FORCE]
        assert len(bf_events) == 1
        assert "10" in bf_events[0].message

    # --- Hydra simülasyonu: çoklu satır ---

    def test_hydra_simulation_multiple_failures_same_ip(self):
        """
        Hydra ile 8 farklı kullanıcı denemesi → her biri SSH_FAILURE olmalı.
        Son satırda count_recent_failures eşiği aşılınca BRUTE_FORCE üretilmeli.
        """
        users = ["root", "admin", "user", "test", "guest", "ubuntu", "pi", "oracle"]
        lines = [_make_failed_line(u, "192.168.56.101") for u in users]

        import server.security_log_parser as parser_module
        db_mock = MagicMock()
        # İlk 4 satırda 4 kayıt var (eşik altı), 5. satırdan itibaren 5+ kayıt
        db_mock.count_recent_failures.side_effect = [1, 2, 3, 4, 5, 6, 7, 8]

        with patch.object(parser_module, "db", db_mock):
            with patch.object(parser_module, "_tail", return_value=lines):
                with patch("pathlib.Path.exists", return_value=True):
                    events = parser_module.parse_auth_log("agent-1", "/fake/auth.log")

        ssh_failures = [e for e in events if e.event_type == SecurityEventType.SSH_FAILURE]
        brute_events = [e for e in events if e.event_type == SecurityEventType.BRUTE_FORCE]

        assert len(ssh_failures) == 8            # Her deneme kaydedildi
        assert len(brute_events) >= 1            # En az bir brute force alarmı
        assert all(e.source_ip == "192.168.56.101" for e in ssh_failures)

    def test_different_ips_tracked_independently(self):
        """İki farklı IP'nin başarısız girişleri birbirini etkilememeli."""
        lines = [
            _make_failed_line("root", "10.0.0.1"),
            _make_failed_line("root", "10.0.0.2"),
        ]
        import server.security_log_parser as parser_module
        db_mock = MagicMock()
        # Her iki IP için de eşik altı
        db_mock.count_recent_failures.return_value = 2

        with patch.object(parser_module, "db", db_mock):
            with patch.object(parser_module, "_tail", return_value=lines):
                with patch("pathlib.Path.exists", return_value=True):
                    events = parser_module.parse_auth_log("agent-1", "/fake/auth.log")

        failures = [e for e in events if e.event_type == SecurityEventType.SSH_FAILURE]
        assert len(failures) == 2
        ips = {e.source_ip for e in failures}
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    # --- DB kayıt kontrolü ---

    def test_events_saved_to_db(self):
        """Tespit edilen olaylar db.save_security_event ile kaydedilmeli."""
        lines = [
            _make_failed_line("root", "1.2.3.4"),
            _make_accepted_line("mehmet", "5.6.7.8"),
        ]
        _, db_mock = self._run(lines, count_recent=0)
        assert db_mock.save_security_event.call_count == 2

    def test_brute_force_event_also_saved_to_db(self):
        """SSH_FAILURE + BRUTE_FORCE: iki ayrı kayıt DB'ye gitmeli."""
        lines = [_make_failed_line("root", "9.9.9.9")]
        _, db_mock = self._run(lines, count_recent=5)
        # SSH_FAILURE + BRUTE_FORCE = 2 kayıt
        assert db_mock.save_security_event.call_count == 2
