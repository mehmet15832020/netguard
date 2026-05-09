"""
agent/log_shipper.py — _collect_suspicious_connections() testleri.
"""
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
        conn = _make_conn("ESTABLISHED", "10.20.30.40", 50000)
        events = self._run([conn])
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
