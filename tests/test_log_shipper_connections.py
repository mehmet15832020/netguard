"""
agent/log_shipper.py — _collect_suspicious_connections() + M1/M2/M5 testleri.
"""
import psutil
from unittest.mock import MagicMock, patch


def _make_conn(status, raddr_ip, raddr_port, laddr_port=54321, pid=None):
    conn = MagicMock()
    conn.status = status
    conn.pid = pid
    conn.raddr = MagicMock()
    conn.raddr.ip = raddr_ip
    conn.raddr.port = raddr_port
    conn.laddr = MagicMock()
    conn.laddr.port = laddr_port
    return conn


class TestCollectSuspiciousConnections:
    def _run(self, conns, local_ip="192.168.1.10"):
        with (
            patch("agent.log_shipper.psutil.net_connections", return_value=conns),
            patch("agent.log_shipper.socket.gethostbyname", return_value=local_ip),
        ):
            from agent.log_shipper import _collect_suspicious_connections
            return _collect_suspicious_connections()

    def test_known_bad_port_reported(self):
        conn = _make_conn("ESTABLISHED", "10.20.30.40", 4444)
        events = self._run([conn])
        assert len(events) == 1
        assert events[0]["event_action"] == "suspicious_outbound_connection"
        assert events[0]["severity"] == "critical"
        assert "4444" in events[0]["message"]

    def test_trusted_port_ignored(self):
        conn = _make_conn("ESTABLISHED", "10.20.30.40", 443)
        events = self._run([conn])
        assert events == []

    def test_loopback_ignored(self):
        conn = _make_conn("ESTABLISHED", "127.0.0.1", 4444)
        events = self._run([conn])
        assert events == []

    def test_local_ip_ignored(self):
        conn = _make_conn("ESTABLISHED", "192.168.1.10", 4444)
        events = self._run([conn], local_ip="192.168.1.10")
        assert events == []

    def test_non_established_ignored(self):
        conn = _make_conn("TIME_WAIT", "10.20.30.40", 4444)
        events = self._run([conn])
        assert events == []

    def test_no_raddr_ignored(self):
        conn = MagicMock()
        conn.status = "ESTABLISHED"
        conn.raddr = None
        events = self._run([conn])
        assert events == []

    def test_high_ephemeral_port_warning(self):
        # Tek bağlantı threshold altında — uyarı üretilmemeli (SUSPICIOUS_CONN_THRESHOLD=5)
        conn = _make_conn("ESTABLISHED", "10.20.30.40", 50000)
        events = self._run([conn])
        assert len(events) == 0

    def test_high_ephemeral_port_burst_warning(self):
        # 5 farklı hedefe ephemeral port bağlantısı → uyarı
        conns = [_make_conn("ESTABLISHED", f"10.20.30.{i}", 50000 + i) for i in range(5)]
        events = self._run(conns)
        assert len(events) == 1
        assert events[0]["severity"] == "warning"

    def test_standard_port_excluded(self):
        for port in [22, 80, 443, 8000, 53]:
            conn = _make_conn("ESTABLISHED", "10.20.30.40", port)
            events = self._run([conn])
            assert events == [], f"Port {port} raporlanmamalı"

    def test_multiple_connections(self):
        conns = [
            _make_conn("ESTABLISHED", "1.2.3.4", 4444),
            _make_conn("ESTABLISHED", "5.6.7.8", 6667),
            _make_conn("ESTABLISHED", "9.10.11.12", 443),
        ]
        events = self._run(conns)
        assert len(events) == 2

    def test_event_contains_remote_ip(self):
        conn = _make_conn("ESTABLISHED", "99.88.77.66", 1337)
        events = self._run([conn])
        assert "99.88.77.66" in events[0]["message"]


# ─────────────────────────────────────────────────────────────────────────────
#  M2 — su failure parse
# ─────────────────────────────────────────────────────────────────────────────

class TestParseLineSuFailure:
    def _parse(self, line):
        from agent.log_shipper import _parse_line
        return _parse_line(line)

    def test_su_failed_line_detected(self):
        line = "su: FAILED SU (to root) mehmet on pts/0"
        ev = self._parse(line)
        assert ev is not None
        assert ev["event_action"] == "su_failure"
        assert "root" in ev["message"]
        assert "mehmet" in ev["message"]

    def test_pam_su_auth_failure_detected(self):
        line = "pam_unix(su:auth): authentication failure; logname=user uid=1000 euid=0 tty=pts/0 ruser=user rhost=  user=root"
        ev = self._parse(line)
        assert ev is not None
        assert ev["event_action"] == "su_failure"
        assert "root" in ev["message"]

    def test_pam_su_l_auth_failure_detected(self):
        line = "pam_unix(su-l:auth): authentication failure; logname= uid=1000 euid=0 tty=pts/0 ruser=alice rhost=  user=root"
        ev = self._parse(line)
        assert ev is not None
        assert ev["event_action"] == "su_failure"

    def test_normal_ssh_not_affected(self):
        line = "Failed password for root from 1.2.3.4 port 22 ssh2"
        ev = self._parse(line)
        assert ev is not None
        assert ev["event_action"] == "ssh_failure"


# ─────────────────────────────────────────────────────────────────────────────
#  M5 — _collect_listening_ports
# ─────────────────────────────────────────────────────────────────────────────

class TestCollectListeningPorts:
    def _make_listen_conn(self, port: int, pid: int = 1234, ip: str = "0.0.0.0"):
        conn = MagicMock()
        conn.status = "LISTEN"
        conn.pid = pid
        conn.raddr = None
        conn.laddr = MagicMock()
        conn.laddr.port = port
        conn.laddr.ip = ip
        return conn

    def _run(self, conns, proc_name="test-proc"):
        with (
            patch("agent.log_shipper.psutil.net_connections", return_value=conns),
            patch("agent.log_shipper.psutil.Process") as mock_proc,
        ):
            mock_proc.return_value.name.return_value = proc_name
            from agent.log_shipper import _collect_listening_ports
            return _collect_listening_ports()

    def test_listen_port_reported(self):
        conn = self._make_listen_conn(8080)
        events = self._run([conn], proc_name="nginx")
        assert len(events) == 1
        assert events[0]["event_action"] == "listening_port"
        assert "8080" in events[0]["message"]
        assert "nginx" in events[0]["message"]

    def test_established_not_included(self):
        conn = MagicMock()
        conn.status = "ESTABLISHED"
        conn.laddr = MagicMock()
        conn.laddr.port = 1234
        conn.laddr.ip = "0.0.0.0"
        conn.raddr = MagicMock()
        events = self._run([conn])
        assert events == []

    def test_multiple_listen_ports(self):
        conns = [self._make_listen_conn(p) for p in [22, 80, 443, 8080]]
        events = self._run(conns)
        assert len(events) == 4

    def test_ipv6_listen_marked_tcp6(self):
        conn = self._make_listen_conn(9000, ip="::1")
        events = self._run([conn])
        assert len(events) == 1
        assert "tcp6" in events[0]["raw_data"]

    def test_access_denied_returns_empty(self):
        with patch("agent.log_shipper.psutil.net_connections", side_effect=psutil.AccessDenied(0)):
            from agent.log_shipper import _collect_listening_ports
            events = _collect_listening_ports()
        assert events == []


# ─────────────────────────────────────────────────────────────────────────────
#  M1 — Position file path
# ─────────────────────────────────────────────────────────────────────────────

class TestPositionFilePath:
    def test_default_path_not_in_tmp(self):
        from agent.log_shipper import POSITION_FILE
        assert not POSITION_FILE.startswith("/tmp/"), \
            f"POSITION_FILE /tmp'de olmamalı (reboot'ta silinir): {POSITION_FILE}"

    def test_default_path_in_var_lib(self):
        import os
        # Env override yoksa /var/lib/netguard altında olmalı
        if not os.getenv("LOG_POSITION_FILE") and not os.getenv("LOG_POSITION_DIR"):
            from agent.log_shipper import POSITION_FILE
            assert "/var/lib/" in POSITION_FILE
