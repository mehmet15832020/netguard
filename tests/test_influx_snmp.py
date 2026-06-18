"""T1 — InfluxWriter.query_snmp_interfaces() unit testleri."""

import pytest
from unittest.mock import MagicMock, patch
from server.influx_writer import InfluxWriter


def _make_writer(enabled: bool = True) -> InfluxWriter:
    w = InfluxWriter.__new__(InfluxWriter)
    w._url = "http://localhost:8086"
    w._token = "test-token" if enabled else ""
    w._org = "netguard"
    w._bucket = "metrics"
    w._client = None
    w._write_api = None
    w._enabled = enabled
    return w


class TestQuerySNMPInterfaces:

    def test_returns_none_when_disabled(self):
        w = _make_writer(enabled=False)
        assert w.query_snmp_interfaces("192.168.1.1") is None

    def test_invalid_host_returns_none(self):
        w = _make_writer(enabled=True)
        assert w.query_snmp_interfaces("host; DROP TABLE--") is None
        assert w.query_snmp_interfaces("") is None
        assert w.query_snmp_interfaces("a" * 200) is None

    def test_valid_ip_host_accepted(self):
        w = _make_writer(enabled=True)
        mock_client = MagicMock()
        mock_qa = MagicMock()
        mock_qa.query.return_value = []
        mock_client.query_api.return_value = mock_qa

        with patch("server.influx_writer.InfluxDBClient", return_value=mock_client):
            result = w.query_snmp_interfaces("192.168.1.1", range="6h")

        assert result is not None
        assert result["host"] == "192.168.1.1"
        assert result["range"] == "6h"
        assert result["interfaces"] == []

    def test_valid_hostname_accepted(self):
        w = _make_writer(enabled=True)
        mock_client = MagicMock()
        mock_qa = MagicMock()
        mock_qa.query.return_value = []
        mock_client.query_api.return_value = mock_qa

        with patch("server.influx_writer.InfluxDBClient", return_value=mock_client):
            result = w.query_snmp_interfaces("vyos-router", range="1h")

        assert result is not None
        assert result["host"] == "vyos-router"

    def test_range_default_6h(self):
        w = _make_writer(enabled=True)
        mock_client = MagicMock()
        mock_qa = MagicMock()
        mock_qa.query.return_value = []
        mock_client.query_api.return_value = mock_qa

        with patch("server.influx_writer.InfluxDBClient", return_value=mock_client):
            result = w.query_snmp_interfaces("192.168.1.1")

        assert result["range"] == "6h"

    def test_influx_exception_returns_none(self):
        w = _make_writer(enabled=True)
        mock_client = MagicMock()
        mock_client.query_api.side_effect = RuntimeError("connection refused")

        with patch("server.influx_writer.InfluxDBClient", return_value=mock_client):
            result = w.query_snmp_interfaces("192.168.1.1")

        assert result is None

    def test_interface_data_structured_correctly(self):
        w = _make_writer(enabled=True)
        mock_client = MagicMock()
        mock_qa = MagicMock()

        def mock_query(flux: str):
            if "bandwidth_in_bps" in flux:
                rec = MagicMock()
                rec.values = {"if_name": "eth0"}
                rec.get_time.return_value = MagicMock(isoformat=lambda: "2024-01-01T00:00:00+00:00")
                rec.get_value.return_value = 1000.0
                table = MagicMock()
                table.records = [rec]
                return [table]
            return []

        mock_qa.query.side_effect = mock_query
        mock_client.query_api.return_value = mock_qa

        with patch("server.influx_writer.InfluxDBClient", return_value=mock_client):
            result = w.query_snmp_interfaces("192.168.1.1", range="6h")

        assert result is not None
        assert len(result["interfaces"]) == 1
        iface = result["interfaces"][0]
        assert iface["if_name"] == "eth0"
        assert len(iface["bw_in"]) == 1
        assert iface["bw_in"][0]["v"] == 1000.0
        assert iface["bw_out"] == []
        assert iface["oper_status"] == []
