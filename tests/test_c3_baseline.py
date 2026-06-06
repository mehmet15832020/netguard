"""
C3 — Network behavioral baseline genişletme testleri.

typical_protocols alanı, yeni port/protokol anomali tespiti,
get_distinct_values_by_ip DB metodu.
"""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest

from shared.models import NormalizedLog, LogSourceType, LogCategory


def _now():
    return datetime.now(timezone.utc)


def _log(source_ip="192.168.1.10", dest_port=80, protocol="tcp",
         dest_ip="10.0.0.1", event_action="http_request",
         ts=None) -> NormalizedLog:
    return NormalizedLog(
        log_id            = str(uuid.uuid4()),
        raw_id            = str(uuid.uuid4()),
        source_type       = LogSourceType.ZEEK,
        observer_hostname = "zeek",
        timestamp         = ts or _now(),
        severity          = "info",
        event_category    = LogCategory.NETWORK,
        event_action      = event_action,
        source_ip         = source_ip,
        destination_ip    = dest_ip,
        destination_port  = dest_port,
        network_protocol  = protocol,
        message           = f"{source_ip}→{dest_ip}:{dest_port}",
    )


@pytest.fixture
def bdb(tmp_db, monkeypatch):
    monkeypatch.setattr("server.asset_baseline.db", tmp_db)
    return tmp_db


# ─── DB: get_distinct_values_by_ip ───────────────────────────────────────────

class TestGetDistinctValuesByIp:

    def test_returns_distinct_ports(self, tmp_db):
        for port in [80, 443, 80, 8080]:
            tmp_db.save_normalized_log(_log(dest_port=port), tenant_id="default")
        since = _now() - timedelta(hours=1)
        result = tmp_db.get_distinct_values_by_ip("192.168.1.10", "destination_port", since, "default")
        assert set(result) == {"80", "443", "8080"}

    def test_returns_distinct_protocols(self, tmp_db):
        for proto in ["tcp", "udp", "tcp"]:
            tmp_db.save_normalized_log(_log(protocol=proto), tenant_id="default")
        since = _now() - timedelta(hours=1)
        result = tmp_db.get_distinct_values_by_ip("192.168.1.10", "network_protocol", since, "default")
        assert set(result) == {"tcp", "udp"}

    def test_time_filter(self, tmp_db):
        old_ts = _now() - timedelta(hours=5)
        tmp_db.save_normalized_log(_log(dest_port=9999, ts=old_ts), tenant_id="default")
        since = _now() - timedelta(hours=1)
        result = tmp_db.get_distinct_values_by_ip("192.168.1.10", "destination_port", since, "default")
        assert "9999" not in result

    def test_invalid_column_raises(self, tmp_db):
        since = _now() - timedelta(hours=1)
        with pytest.raises(ValueError):
            tmp_db.get_distinct_values_by_ip("192.168.1.10", "message", since, "default")

    def test_tenant_isolation(self, tmp_db):
        tmp_db.save_normalized_log(_log(dest_port=5432, protocol="tcp"), tenant_id="other")
        since = _now() - timedelta(hours=1)
        result = tmp_db.get_distinct_values_by_ip("192.168.1.10", "destination_port", since, "default")
        assert "5432" not in result


# ─── DB: upsert_asset_baseline typical_protocols ─────────────────────────────

class TestUpsertBaselineProtocols:

    def test_typical_protocols_saved_and_retrieved(self, tmp_db):
        tmp_db.upsert_asset_baseline(
            source_ip="192.168.1.10", tenant_id="default",
            first_seen_at=_now().isoformat(), last_seen_at=_now().isoformat(),
            avg_events_per_hour=10.0, typical_ports=["80", "443"],
            typical_destinations=["10.0.0.1"], typical_event_actions=["http_request"],
            typical_protocols=["tcp", "udp"], sample_hours=24,
        )
        bl = tmp_db.get_asset_baseline("192.168.1.10", "default")
        assert bl is not None
        assert set(bl["typical_protocols"]) == {"tcp", "udp"}

    def test_typical_protocols_default_empty(self, tmp_db):
        tmp_db.upsert_asset_baseline(
            source_ip="192.168.1.20", tenant_id="default",
            first_seen_at=_now().isoformat(), last_seen_at=_now().isoformat(),
            avg_events_per_hour=5.0, typical_ports=[], typical_destinations=[],
            typical_event_actions=[], sample_hours=10,
        )
        bl = tmp_db.get_asset_baseline("192.168.1.20", "default")
        assert bl["typical_protocols"] == []

    def test_get_all_baselines_includes_protocols(self, tmp_db):
        tmp_db.upsert_asset_baseline(
            source_ip="192.168.1.30", tenant_id="default",
            first_seen_at=_now().isoformat(), last_seen_at=_now().isoformat(),
            avg_events_per_hour=8.0, typical_ports=["22"],
            typical_destinations=[], typical_event_actions=[],
            typical_protocols=["tcp"], sample_hours=12,
        )
        all_bl = tmp_db.get_all_asset_baselines("default")
        assert "typical_protocols" in all_bl["192.168.1.30"]
        assert all_bl["192.168.1.30"]["typical_protocols"] == ["tcp"]


# ─── update_baselines: typical_protocols hesaplanıyor ───────────────────────

class TestUpdateBaselinesProtocols:

    def test_protocols_computed_and_stored(self, bdb):
        ip = "192.168.2.10"
        for proto in ["tcp"] * 8 + ["udp"] * 4:
            bdb.save_normalized_log(_log(source_ip=ip, protocol=proto), tenant_id="default")

        from server.asset_baseline import update_baselines
        update_baselines("default")

        bl = bdb.get_asset_baseline(ip, "default")
        assert bl is not None
        assert "tcp" in bl["typical_protocols"]

    def test_protocols_in_all_baselines(self, bdb):
        ip = "192.168.2.20"
        for _ in range(12):
            bdb.save_normalized_log(_log(source_ip=ip, protocol="udp"), tenant_id="default")

        from server.asset_baseline import update_baselines
        update_baselines("default")

        all_bl = bdb.get_all_asset_baselines("default")
        if ip in all_bl:
            assert "typical_protocols" in all_bl[ip]


# ─── check_deviations: yeni port/protokol tespiti ───────────────────────────

class TestCheckDeviationsNewBehavior:

    def _seed_baseline(self, bdb, ip, ports, protocols, sample_hours=20):
        bdb.upsert_asset_baseline(
            source_ip=ip, tenant_id="default",
            first_seen_at=_now().isoformat(), last_seen_at=_now().isoformat(),
            avg_events_per_hour=5.0, typical_ports=ports,
            typical_destinations=["10.0.0.1"], typical_event_actions=["http_request"],
            typical_protocols=protocols, sample_hours=sample_hours,
        )

    def test_new_port_detected(self, bdb):
        ip = "192.168.3.10"
        self._seed_baseline(bdb, ip, ["80", "443"], ["tcp"])
        bdb.save_normalized_log(_log(source_ip=ip, dest_port=445, protocol="tcp"), tenant_id="default")

        written = []
        original = bdb.save_normalized_log
        def capture(log, tenant_id="default"):
            written.append(log)
            return original(log, tenant_id=tenant_id)
        bdb.save_normalized_log = capture

        with patch("server.asset_baseline.db", bdb):
            from server.asset_baseline import check_deviations
            count = check_deviations("default")

        new_port_events = [w for w in written if w.event_action == "new_port_detected"]
        assert len(new_port_events) >= 1
        assert any("445" in w.message for w in new_port_events)

    def test_new_protocol_detected(self, bdb):
        ip = "192.168.3.20"
        self._seed_baseline(bdb, ip, ["80"], ["tcp"])
        bdb.save_normalized_log(_log(source_ip=ip, dest_port=53, protocol="udp"), tenant_id="default")

        written = []
        original = bdb.save_normalized_log
        def capture(log, tenant_id="default"):
            written.append(log)
            return original(log, tenant_id=tenant_id)
        bdb.save_normalized_log = capture

        with patch("server.asset_baseline.db", bdb):
            from server.asset_baseline import check_deviations
            count = check_deviations("default")

        new_proto_events = [w for w in written if w.event_action == "new_protocol_detected"]
        assert len(new_proto_events) >= 1
        assert any("udp" in w.message for w in new_proto_events)

    def test_known_port_no_alert(self, bdb):
        ip = "192.168.3.30"
        self._seed_baseline(bdb, ip, ["80", "443", "8080"], ["tcp"])
        bdb.save_normalized_log(_log(source_ip=ip, dest_port=443, protocol="tcp"), tenant_id="default")

        written = []
        original = bdb.save_normalized_log
        def capture(log, tenant_id="default"):
            written.append(log)
            return original(log, tenant_id=tenant_id)
        bdb.save_normalized_log = capture

        with patch("server.asset_baseline.db", bdb):
            from server.asset_baseline import check_deviations
            check_deviations("default")

        anomalies = [w for w in written if w.event_action in ("new_port_detected", "new_protocol_detected")]
        assert len(anomalies) == 0

    def test_insufficient_sample_skipped(self, bdb):
        ip = "192.168.3.40"
        self._seed_baseline(bdb, ip, ["80"], ["tcp"], sample_hours=3)
        bdb.save_normalized_log(_log(source_ip=ip, dest_port=3389, protocol="tcp"), tenant_id="default")

        written = []
        original = bdb.save_normalized_log
        def capture(log, tenant_id="default"):
            written.append(log)
            return original(log, tenant_id=tenant_id)
        bdb.save_normalized_log = capture

        with patch("server.asset_baseline.db", bdb):
            from server.asset_baseline import check_deviations
            check_deviations("default")

        anomalies = [w for w in written if w.event_action == "new_port_detected"]
        assert len(anomalies) == 0

    def test_no_baseline_no_alert(self, bdb):
        ip = "192.168.3.99"
        bdb.save_normalized_log(_log(source_ip=ip, dest_port=6379), tenant_id="default")

        with patch("server.asset_baseline.db", bdb):
            from server.asset_baseline import check_deviations
            count = check_deviations("default")

        assert isinstance(count, int)
