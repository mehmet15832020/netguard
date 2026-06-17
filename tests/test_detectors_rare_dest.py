"""NetGuard — Rare External Destination Detector (I3) testleri."""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from shared.models import LogCategory, LogSourceType, NormalizedLog


def _make_log(src_ip: str, dst_ip: str, dst_port: int = 443) -> NormalizedLog:
    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.NETFLOW,
        observer_hostname="netguard",
        timestamp=datetime.now(timezone.utc),
        severity="info",
        event_category=LogCategory.NETWORK,
        event_action="netflow_record",
        source_ip=src_ip,
        destination_ip=dst_ip,
        destination_port=dst_port,
        network_protocol="tcp",
        message=f"{src_ip} → {dst_ip}:{dst_port}",
    )


class TestIsExternal:
    def test_public_ip_is_external(self):
        from server.detectors.rare_dest import _is_external
        assert _is_external("8.8.8.8") is True

    def test_rfc1918_10_not_external(self):
        from server.detectors.rare_dest import _is_external
        assert _is_external("10.0.0.1") is False

    def test_rfc1918_192168_not_external(self):
        from server.detectors.rare_dest import _is_external
        assert _is_external("192.168.1.1") is False

    def test_rfc1918_172_not_external(self):
        from server.detectors.rare_dest import _is_external
        assert _is_external("172.16.0.1") is False

    def test_loopback_not_external(self):
        from server.detectors.rare_dest import _is_external
        assert _is_external("127.0.0.1") is False

    def test_none_not_external(self):
        from server.detectors.rare_dest import _is_external
        assert _is_external(None) is False


class TestDetectRareExternalDestinations:
    def _call(self, new_logs, known_map=None):
        """detect_rare_external_destinations'ı mock DB ile çağır."""
        from server.detectors.rare_dest import detect_rare_external_destinations

        if known_map is None:
            known_map = {}

        with patch("server.detectors.rare_dest.db") as mock_db:
            mock_db.get_known_destination_ips.return_value = known_map
            return detect_rare_external_destinations(new_logs)

    def test_known_external_destination_no_alert(self):
        """Daha önce görülmüş harici IP → alert üretilmemeli."""
        log = _make_log("192.168.1.10", "1.1.1.1")
        known = {"192.168.1.10": {"1.1.1.1", "8.8.8.8"}}
        alerts = self._call([log], known_map=known)
        assert alerts == []

    def test_new_external_destination_alert(self):
        """İlk kez görülen harici IP → alert üretilmeli."""
        log = _make_log("192.168.1.10", "203.0.113.5", dst_port=443)
        known = {"192.168.1.10": {"1.1.1.1"}}
        alerts = self._call([log], known_map=known)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.event_action == "rare_external_destination"
        assert alert.source_ip == "192.168.1.10"
        assert alert.destination_ip == "203.0.113.5"
        assert alert.destination_port == 443
        assert "rare_dest" in alert.tags
        assert alert.severity == "warning"

    def test_internal_destination_no_alert(self):
        """İç IP hedefli bağlantı → alert üretilmemeli."""
        log = _make_log("192.168.1.10", "10.0.0.5")
        alerts = self._call([log])
        assert alerts == []

    def test_empty_logs_no_alert(self):
        """Boş log listesi → boş sonuç."""
        alerts = self._call([])
        assert alerts == []

    def test_multiple_logs_partial_known(self):
        """Birden fazla log — sadece bilinmeyenler alert üretir."""
        log_known = _make_log("192.168.1.10", "8.8.8.8")
        log_new = _make_log("192.168.1.10", "203.0.113.99")
        log_internal = _make_log("192.168.1.10", "10.0.0.1")
        known = {"192.168.1.10": {"8.8.8.8"}}
        alerts = self._call([log_known, log_new, log_internal], known_map=known)
        assert len(alerts) == 1
        assert alerts[0].destination_ip == "203.0.113.99"

    def test_disabled_via_env(self, monkeypatch):
        """RARE_DEST_DETECTOR=false → tespit devre dışı."""
        monkeypatch.setenv("RARE_DEST_DETECTOR", "false")
        import importlib
        import server.detectors.rare_dest as rd_mod
        importlib.reload(rd_mod)

        log = _make_log("192.168.1.10", "203.0.113.5")
        alerts = rd_mod.detect_rare_external_destinations([log])
        assert alerts == []

        monkeypatch.setenv("RARE_DEST_DETECTOR", "true")
        importlib.reload(rd_mod)

    def test_db_error_returns_empty(self):
        """DB sorgusu başarısız olursa boş liste döner, exception fırlatmaz."""
        from server.detectors.rare_dest import detect_rare_external_destinations
        log = _make_log("192.168.1.10", "203.0.113.5")

        with patch("server.detectors.rare_dest.db") as mock_db:
            mock_db.get_known_destination_ips.side_effect = Exception("DB down")
            alerts = detect_rare_external_destinations([log])

        assert alerts == []

    def test_alert_message_includes_port(self):
        """Alert mesajı destination IP ve port bilgisini içermeli."""
        log = _make_log("10.0.0.5", "198.51.100.1", dst_port=8080)
        known = {}
        alerts = self._call([log], known_map=known)
        assert len(alerts) == 1
        assert "198.51.100.1" in alerts[0].message
        assert "8080" in alerts[0].message

    def test_no_source_ip_skipped(self):
        """source_ip eksik log → atlanmalı."""
        log = _make_log("192.168.1.10", "203.0.113.5")
        log = log.model_copy(update={"source_ip": None})
        alerts = self._call([log])
        assert alerts == []

    def test_no_destination_ip_skipped(self):
        """destination_ip eksik log → atlanmalı."""
        log = _make_log("192.168.1.10", "203.0.113.5")
        log = log.model_copy(update={"destination_ip": None})
        alerts = self._call([log])
        assert alerts == []


class TestGetKnownDestinationIps:
    def test_returns_empty_for_empty_list(self, tmp_db):
        result = tmp_db.get_known_destination_ips(
            source_ips=[],
            since=datetime.now(timezone.utc) - timedelta(hours=24),
        )
        assert result == {}

    def test_returns_known_destinations(self, tmp_db):
        from server.database import DatabaseManager

        since = datetime.now(timezone.utc) - timedelta(hours=1)
        log = NormalizedLog(
            log_id=str(uuid.uuid4()),
            raw_id=str(uuid.uuid4()),
            source_type=LogSourceType.NETFLOW,
            observer_hostname="netguard",
            timestamp=datetime.now(timezone.utc),
            severity="info",
            event_category=LogCategory.NETWORK,
            event_action="netflow_record",
            source_ip="192.168.1.50",
            destination_ip="8.8.8.8",
            message="test",
        )
        tmp_db.save_normalized_log(log)

        result = tmp_db.get_known_destination_ips(
            source_ips=["192.168.1.50"],
            since=since,
        )
        assert "192.168.1.50" in result
        assert "8.8.8.8" in result["192.168.1.50"]

    def test_excludes_entries_before_since(self, tmp_db):
        old_ts = datetime.now(timezone.utc) - timedelta(hours=30)
        log = NormalizedLog(
            log_id=str(uuid.uuid4()),
            raw_id=str(uuid.uuid4()),
            source_type=LogSourceType.NETFLOW,
            observer_hostname="netguard",
            timestamp=old_ts,
            received_at=old_ts,
            severity="info",
            event_category=LogCategory.NETWORK,
            event_action="netflow_record",
            source_ip="192.168.1.51",
            destination_ip="1.1.1.1",
            message="test",
        )
        tmp_db.save_normalized_log(log)

        result = tmp_db.get_known_destination_ips(
            source_ips=["192.168.1.51"],
            since=datetime.now(timezone.utc) - timedelta(hours=24),
        )
        assert "192.168.1.51" not in result
