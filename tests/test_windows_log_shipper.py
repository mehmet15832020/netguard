"""Windows log shipper testleri — platform-bağımsız bölümler."""

import sys
from unittest.mock import MagicMock, patch
from agent.windows_log_shipper import (
    _read_position,
    _write_position,
    _LOGON_TYPES,
    WATCHED_EVENT_IDS,
    EID_LOGON_SUCCESS,
    EID_LOGON_FAILURE,
    EID_PROCESS_CREATE,
    WindowsLogShipper,
)


class TestConstants:
    def test_watched_event_ids_contains_required(self):
        assert 4624 in WATCHED_EVENT_IDS
        assert 4625 in WATCHED_EVENT_IDS
        assert 4688 in WATCHED_EVENT_IDS

    def test_logon_type_labels(self):
        assert _LOGON_TYPES["2"] == "interactive"
        assert _LOGON_TYPES["3"] == "network"
        assert _LOGON_TYPES["5"] == "service"
        assert _LOGON_TYPES["10"] == "remote_interactive"


class TestPositionFile:
    def test_read_position_missing_file_returns_zero(self, tmp_path):
        with patch("agent.windows_log_shipper.POSITION_FILE", str(tmp_path / "pos.txt")):
            assert _read_position() == 0

    def test_write_and_read_position(self, tmp_path):
        pos_file = str(tmp_path / "pos.txt")
        with patch("agent.windows_log_shipper.POSITION_FILE", pos_file):
            _write_position(12345)
            assert _read_position() == 12345

    def test_write_position_creates_parent_dirs(self, tmp_path):
        deep = tmp_path / "a" / "b" / "pos.txt"
        with patch("agent.windows_log_shipper.POSITION_FILE", str(deep)):
            _write_position(99)
            assert _read_position() == 99


class TestWindowsLogShipperInit:
    def test_start_on_linux_logs_warning(self, caplog):
        import logging
        shipper = WindowsLogShipper(server_url="http://localhost:8000", api_key="key")
        with patch("agent.windows_log_shipper.sys") as mock_sys:
            mock_sys.platform = "linux"
            with caplog.at_level(logging.WARNING, logger="agent.windows_log_shipper"):
                shipper.start()
        assert shipper._thread is None  # thread başlamamalı

    def test_start_without_api_key_disabled(self, caplog):
        import logging
        shipper = WindowsLogShipper(server_url="http://localhost:8000", api_key="")
        with patch("agent.windows_log_shipper.sys") as mock_sys:
            mock_sys.platform = "win32"
            with caplog.at_level(logging.WARNING, logger="agent.windows_log_shipper"):
                shipper.start()
        assert shipper._thread is None


class TestCollectNewEventsWithoutWin32:
    def test_returns_empty_when_win32_missing(self):
        from agent.windows_log_shipper import _collect_new_events
        with patch.dict("sys.modules", {"win32evtlog": None, "win32con": None}):
            result = _collect_new_events()
        assert result == []
