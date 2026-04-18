"""
SNMP Trap Receiver testleri.
"""

import pytest
from unittest.mock import patch, MagicMock

from server.snmp_trap_receiver import _parse_trap, SNMPTrapProtocol


class TestParseTrap:
    def test_short_packet(self):
        result = _parse_trap(b"\x30\x05", "10.0.0.1")
        assert "byte" in result
        assert isinstance(result, str)

    def test_v2c_trap_detected(self):
        # Minimal SNMPv2c benzeri payload (version byte = 1 at position 4)
        data = bytes([0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70])
        data += b"\x00" * 30
        result = _parse_trap(data, "10.0.0.2")
        assert "10.0.0.2" in result
        assert isinstance(result, str)

    def test_arbitrary_bytes_no_exception(self):
        # Rastgele baytlar exception fırlatmamalı
        for payload in [b"\xff" * 20, b"\x00" * 10, b"hello world!"]:
            result = _parse_trap(payload, "1.2.3.4")
            assert isinstance(result, str)


class TestSNMPTrapProtocol:
    def test_datagram_received_no_exception(self):
        """Geçersiz veri geldiğinde exception olmamalı."""
        proto = SNMPTrapProtocol()
        proto.datagram_received(b"\xff\xff\xff", ("10.0.0.1", 162))

    def test_datagram_writes_to_db(self, tmp_db):
        """Geçerli trap → security_events'e kayıt."""
        proto = SNMPTrapProtocol()
        data = bytes([0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06]) + b"\x00" * 30
        with patch("server.database.db", tmp_db):
            proto.datagram_received(data, ("10.0.0.5", 162))
        events = tmp_db.get_security_events(limit=10)
        # get_security_events SecurityEvent nesneleri döndürür
        assert any(
            (e.event_type.value if hasattr(e.event_type, "value") else e.event_type) == "snmp_trap"
            for e in events
        )

    def test_error_received_no_exception(self):
        proto = SNMPTrapProtocol()
        proto.error_received(OSError("test"))

    def test_connection_lost_no_exception(self):
        proto = SNMPTrapProtocol()
        proto.connection_lost(None)
        proto.connection_lost(OSError("dropped"))
