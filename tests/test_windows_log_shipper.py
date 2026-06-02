"""Windows log shipper testleri — platform-bağımsız bölümler."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent.windows_log_shipper import (
    _read_position,
    _write_position,
    _position_file,
    _CHANNELS,
    WindowsLogShipper,
)


class TestChannelDefinitions:
    def test_all_channels_defined(self):
        assert "Security" in _CHANNELS
        assert "Sysmon" in _CHANNELS
        assert "PowerShell" in _CHANNELS
        assert "System" in _CHANNELS
        assert "AppLocker" in _CHANNELS

    def test_security_channel_eids(self):
        _, eids = _CHANNELS["Security"]
        assert 4624 in eids
        assert 4625 in eids
        assert 4688 in eids
        assert 4741 in eids
        assert 4614 in eids
        assert 4703 in eids

    def test_sysmon_channel_new_eids(self):
        _, eids = _CHANNELS["Sysmon"]
        assert 8 in eids
        assert 9 in eids
        assert 15 in eids
        assert 17 in eids
        assert 18 in eids
        assert 19 in eids
        assert 21 in eids
        assert 25 in eids

    def test_powershell_channel_eids(self):
        _, eids = _CHANNELS["PowerShell"]
        assert 4103 in eids
        assert 4104 in eids

    def test_system_channel_eids(self):
        _, eids = _CHANNELS["System"]
        assert 7045 in eids
        assert 7034 in eids
        assert 7040 in eids

    def test_applocker_channel_eids(self):
        _, eids = _CHANNELS["AppLocker"]
        assert 8004 in eids

    def test_channel_eids_are_frozensets(self):
        for name, (log_name, eids) in _CHANNELS.items():
            assert isinstance(eids, frozenset), f"{name} kanalı frozenset olmalı"

    def test_channel_log_names_are_strings(self):
        for name, (log_name, _) in _CHANNELS.items():
            assert isinstance(log_name, str), f"{name} log_name string olmalı"
            assert log_name, f"{name} log_name boş olmamalı"


class TestPositionFile:
    def test_position_file_per_channel(self):
        sec = _position_file("Security")
        sysmon = _position_file("Sysmon")
        ps = _position_file("PowerShell")
        assert sec != sysmon
        assert sysmon != ps
        assert "Security" in str(sec)
        assert "Sysmon" in str(sysmon)

    def test_position_file_slash_replaced(self):
        result = _position_file("Microsoft-Windows-Sysmon/Operational")
        assert "/" not in result.name

    def test_read_position_missing_file_returns_zero(self, tmp_path):
        with patch("agent.windows_log_shipper.POSITION_DIR", tmp_path):
            assert _read_position("Security") == 0

    def test_write_and_read_position(self, tmp_path):
        with patch("agent.windows_log_shipper.POSITION_DIR", tmp_path):
            _write_position("Security", 12345)
            assert _read_position("Security") == 12345

    def test_write_position_creates_parent_dirs(self, tmp_path):
        deep = tmp_path / "a" / "b"
        with patch("agent.windows_log_shipper.POSITION_DIR", deep):
            _write_position("Security", 99)
            assert _read_position("Security") == 99

    def test_channels_have_separate_positions(self, tmp_path):
        with patch("agent.windows_log_shipper.POSITION_DIR", tmp_path):
            _write_position("Security", 100)
            _write_position("Sysmon", 200)
            assert _read_position("Security") == 100
            assert _read_position("Sysmon") == 200


class TestWindowsLogShipperInit:
    def test_start_on_linux_logs_warning(self, caplog):
        import logging
        shipper = WindowsLogShipper(server_url="http://localhost:8000", api_key="key")
        with patch("agent.windows_log_shipper.sys") as mock_sys:
            mock_sys.platform = "linux"
            with caplog.at_level(logging.WARNING, logger="agent.windows_log_shipper"):
                shipper.start()
        assert shipper._thread is None

    def test_start_without_api_key_disabled(self, caplog):
        import logging
        shipper = WindowsLogShipper(server_url="http://localhost:8000", api_key="")
        with patch("agent.windows_log_shipper.sys") as mock_sys:
            mock_sys.platform = "win32"
            with caplog.at_level(logging.WARNING, logger="agent.windows_log_shipper"):
                shipper.start()
        assert shipper._thread is None

    def test_ship_strips_channel_key(self):
        shipper = WindowsLogShipper(server_url="http://localhost:8000", api_key="test-key")
        sent_payload = {}

        def fake_post(url, json, headers):
            sent_payload.update(json)
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            return mock_resp

        shipper._client.post = fake_post
        events = [{"event_action": "windows_logon_success", "_channel": "Security"}]
        shipper._ship(events)
        assert "_channel" not in sent_payload["events"][0]
        assert sent_payload["events"][0]["event_action"] == "windows_logon_success"


class TestCollectChannelWithoutWin32:
    def test_returns_empty_when_win32_missing(self):
        from agent.windows_log_shipper import _collect_channel
        with patch.dict("sys.modules", {"win32evtlog": None}):
            result = _collect_channel("Security")
        assert result == []
