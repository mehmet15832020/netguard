"""U4 — C2 Beaconing dedektörü testleri.

MITRE ATT&CK T1071 (Application Layer Protocol) tespiti.
IAT istatistik algoritması: mean_iat, jitter (CV), min bağlantı sayısı.
"""

import math
import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from server.detectors.beaconing import BeaconingDetector


# ── Yardımcılar ───────────────────────────────────────────────────────────────

def _ts(base: datetime, offset_seconds: float) -> str:
    return (base + timedelta(seconds=offset_seconds)).isoformat()


def _insert_connections(
    db_instance,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    timestamps: list[datetime],
    event_action: str = "network_connection",
):
    """normalized_logs'a belirtilen timestamp listesi ile bağlantı kayıtları ekle."""
    with db_instance._connect() as conn:
        for ts in timestamps:
            ts_iso = ts.isoformat()
            conn.execute(
                """
                INSERT INTO normalized_logs
                  (log_id, raw_id, source_type, observer_hostname,
                   timestamp, received_at, processed_at,
                   severity, event_category, event_action,
                   source_ip, destination_ip, destination_port,
                   network_protocol, message, tenant_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    str(uuid.uuid4()), str(uuid.uuid4()), "zeek", "zeek-sensor",
                    ts_iso, ts_iso, ts_iso, "info", "network", event_action,
                    src_ip, dst_ip, dst_port, "tcp",
                    f"Conn: {src_ip} → {dst_ip}:{dst_port}", "default",
                ),
            )


def _make_detector(db_instance, monkeypatch, **kwargs) -> BeaconingDetector:
    """Yeni bir BeaconingDetector üret, db'sini monkeypatch ile geçersiz kıl."""
    import server.detectors.beaconing as bmod
    monkeypatch.setattr(bmod, "db", db_instance)
    return BeaconingDetector(**kwargs)


def _regular_beacon(
    base: datetime,
    count: int = 10,
    interval: float = 60.0,
    jitter_pct: float = 0.0,
) -> list[datetime]:
    """Düzenli aralıklarla beacon zaman damgası listesi üretir."""
    import random
    random.seed(42)
    times = []
    t = base
    for _ in range(count):
        jitter = random.uniform(-jitter_pct, jitter_pct) * interval
        times.append(t)
        t += timedelta(seconds=interval + jitter)
    return times


# ── Birim Testleri: IAT Algoritması ──────────────────────────────────────────

class TestBeaconingAlgorithm:
    """Dedektörün karar mantığını doğrular — DB'ye dokunmaz."""

    def test_below_min_connections_no_alert(self, tmp_db, monkeypatch):
        base = datetime.now(timezone.utc) - timedelta(minutes=15)
        times = _regular_beacon(base, count=5, interval=60.0)
        _insert_connections(tmp_db, "10.1.1.1", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, min_connections=6, window_seconds=1800)
        assert det.detect() == []

    def test_exact_min_connections_alerts(self, tmp_db, monkeypatch):
        base = datetime.now(timezone.utc) - timedelta(minutes=15)
        times = _regular_beacon(base, count=6, interval=60.0)
        _insert_connections(tmp_db, "10.1.1.1", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, min_connections=6, window_seconds=1800)
        logs = det.detect()
        assert len(logs) == 1
        assert logs[0].event_action == "c2_beaconing"

    def test_mean_iat_too_short_no_alert(self, tmp_db, monkeypatch):
        base = datetime.now(timezone.utc) - timedelta(minutes=5)
        times = _regular_beacon(base, count=10, interval=5.0)
        _insert_connections(tmp_db, "10.1.1.1", "5.5.5.5", 80, times)
        det = _make_detector(tmp_db, monkeypatch, min_iat=30.0, window_seconds=1800)
        assert det.detect() == []

    def test_mean_iat_too_long_no_alert(self, tmp_db, monkeypatch):
        base = datetime.now(timezone.utc) - timedelta(hours=1)
        times = _regular_beacon(base, count=8, interval=400.0)
        _insert_connections(tmp_db, "10.1.1.1", "5.5.5.5", 8080, times)
        det = _make_detector(tmp_db, monkeypatch, max_iat=300.0, window_seconds=7200)
        assert det.detect() == []

    def test_high_jitter_no_alert(self, tmp_db, monkeypatch):
        """Yüksek jitter → C2 değil, normal trafik."""
        base = datetime.now(timezone.utc) - timedelta(minutes=30)
        times = _regular_beacon(base, count=10, interval=60.0, jitter_pct=0.40)
        _insert_connections(tmp_db, "10.1.1.1", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, jitter_threshold=0.20, window_seconds=1800)
        assert det.detect() == []

    def test_cobalt_strike_default_60s(self, tmp_db, monkeypatch):
        """Cobalt Strike varsayılan 60s beacon → tespit edilmeli."""
        base = datetime.now(timezone.utc) - timedelta(minutes=20)
        times = _regular_beacon(base, count=12, interval=60.0, jitter_pct=0.05)
        _insert_connections(tmp_db, "192.168.1.100", "203.0.113.50", 443, times)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        logs = det.detect()
        assert len(logs) == 1
        assert logs[0].source_ip == "192.168.1.100"
        assert logs[0].destination_ip == "203.0.113.50"
        assert logs[0].destination_port == 443
        assert logs[0].severity == "high"

    def test_apt1_5min_beacon(self, tmp_db, monkeypatch):
        """APT1 tarzı 300s beacon ±%10 jitter → tespit edilmeli."""
        base = datetime.now(timezone.utc) - timedelta(hours=1)
        times = _regular_beacon(base, count=8, interval=300.0, jitter_pct=0.08)
        _insert_connections(tmp_db, "192.168.1.50", "198.51.100.10", 8443, times)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=7200)
        logs = det.detect()
        assert len(logs) == 1
        assert logs[0].event_action == "c2_beaconing"

    def test_message_contains_mitre_tag(self, tmp_db, monkeypatch):
        base = datetime.now(timezone.utc) - timedelta(minutes=15)
        times = _regular_beacon(base, count=8, interval=60.0)
        _insert_connections(tmp_db, "10.0.0.5", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        logs = det.detect()
        assert "T1071" in logs[0].message
        assert "c2_beaconing" in logs[0].tags

    def test_normalized_log_fields_populated(self, tmp_db, monkeypatch):
        base = datetime.now(timezone.utc) - timedelta(minutes=15)
        times = _regular_beacon(base, count=8, interval=60.0)
        _insert_connections(tmp_db, "10.0.0.5", "1.2.3.4", 4444, times)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        log = det.detect()[0]
        assert log.source_ip == "10.0.0.5"
        assert log.destination_ip == "1.2.3.4"
        assert log.destination_port == 4444
        assert log.severity == "high"
        assert log.event_action == "c2_beaconing"
        assert log.log_id is not None


# ── Çapraz Testler: Çoklu Kaynak / Port Ayrımı ───────────────────────────────

class TestBeaconingMultiTarget:
    """Birden fazla (src, dst, port) grubunu bağımsız değerlendirir."""

    def test_two_independent_beacons(self, tmp_db, monkeypatch):
        base = datetime.now(timezone.utc) - timedelta(minutes=20)
        times1 = _regular_beacon(base, count=8, interval=60.0)
        times2 = _regular_beacon(base, count=8, interval=120.0)
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443,  times1)
        _insert_connections(tmp_db, "10.0.0.2", "8.8.8.8", 8080, times2)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        logs = det.detect()
        assert len(logs) == 2
        src_ips = {l.source_ip for l in logs}
        assert src_ips == {"10.0.0.1", "10.0.0.2"}

    def test_same_src_dst_different_ports(self, tmp_db, monkeypatch):
        """Aynı kaynak→hedef ama farklı portlar: ayrı grup."""
        base = datetime.now(timezone.utc) - timedelta(minutes=20)
        times = _regular_beacon(base, count=8, interval=60.0)
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, times)
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 80,  times)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        logs = det.detect()
        assert len(logs) == 2
        ports = {l.destination_port for l in logs}
        assert ports == {443, 80}

    def test_normal_traffic_not_flagged(self, tmp_db, monkeypatch):
        """Yüksek jitterli trafik: C2 değil."""
        base = datetime.now(timezone.utc) - timedelta(minutes=20)
        times_beacon = _regular_beacon(base, count=8, interval=60.0)
        times_normal = _regular_beacon(base, count=8, interval=60.0, jitter_pct=0.50)
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, times_beacon)
        _insert_connections(tmp_db, "10.0.0.2", "9.9.9.9", 53,  times_normal)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        logs = det.detect()
        assert len(logs) == 1
        assert logs[0].source_ip == "10.0.0.1"

    def test_missing_fields_skipped(self, tmp_db, monkeypatch):
        """destination_ip veya destination_port NULL kayıtlar atlanır."""
        ts_iso = datetime.now(timezone.utc).isoformat()
        with tmp_db._connect() as conn:
            conn.execute(
                "INSERT INTO normalized_logs "
                "(log_id, raw_id, source_type, observer_hostname, timestamp, received_at, processed_at, "
                "severity, event_category, event_action, source_ip, message, tenant_id) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (str(uuid.uuid4()), str(uuid.uuid4()), "zeek", "zeek-sensor",
                 ts_iso, ts_iso, ts_iso, "info", "network", "network_connection",
                 "10.0.0.9", "test", "default"),
            )
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        assert det.detect() == []


# ── Pencere ve Eski Kayıt Testleri ───────────────────────────────────────────

class TestBeaconingWindow:
    def test_old_connections_outside_window(self, tmp_db, monkeypatch):
        """Pencere dışındaki bağlantılar sayılmamalı."""
        base = datetime.now(timezone.utc) - timedelta(hours=2)
        times = _regular_beacon(base, count=10, interval=60.0)
        _insert_connections(tmp_db, "10.1.1.1", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        assert det.detect() == []

    def test_mixed_old_new_connections(self, tmp_db, monkeypatch):
        """Pencere içinde min bağlantı sayısı karşılanmazsa alarm üretme."""
        base_old = datetime.now(timezone.utc) - timedelta(hours=2)
        base_new = datetime.now(timezone.utc) - timedelta(minutes=10)
        times_old = _regular_beacon(base_old, count=8, interval=60.0)
        times_new = _regular_beacon(base_new, count=3, interval=60.0)
        _insert_connections(tmp_db, "10.1.1.1", "5.5.5.5", 443, times_old + times_new)
        det = _make_detector(tmp_db, monkeypatch, min_connections=6, window_seconds=1800)
        assert det.detect() == []

    def test_zeek_connection_event_action(self, tmp_db, monkeypatch):
        """zeek_connection event_action da tespit edilmeli."""
        base = datetime.now(timezone.utc) - timedelta(minutes=20)
        times = _regular_beacon(base, count=8, interval=60.0)
        _insert_connections(
            tmp_db, "10.0.0.5", "5.5.5.5", 443, times,
            event_action="zeek_connection",
        )
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        logs = det.detect()
        assert len(logs) == 1
        assert logs[0].event_action == "c2_beaconing"


# ── Cooldown / Tekrar Alarm Testleri ─────────────────────────────────────────

class TestBeaconingCooldown:
    def test_same_tuple_not_alerted_twice(self, tmp_db, monkeypatch):
        """Aynı (src, dst, port) için cooldown dolmadan tekrar alarm üretilmez."""
        base = datetime.now(timezone.utc) - timedelta(minutes=15)
        times = _regular_beacon(base, count=8, interval=60.0)
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        logs1 = det.detect()
        logs2 = det.detect()
        assert len(logs1) == 1
        assert len(logs2) == 0

    def test_reset_alerted_allows_rereport(self, tmp_db, monkeypatch):
        """reset_alerted() sonrası aynı tuple tekrar raporlanabilir."""
        base = datetime.now(timezone.utc) - timedelta(minutes=15)
        times = _regular_beacon(base, count=8, interval=60.0)
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        det.detect()
        det.reset_alerted()
        logs = det.detect()
        assert len(logs) == 1

    def test_different_tuple_after_cooldown(self, tmp_db, monkeypatch):
        """Farklı tuple her zaman alarm üretebilir."""
        base = datetime.now(timezone.utc) - timedelta(minutes=15)
        times = _regular_beacon(base, count=8, interval=60.0)
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, times)
        _insert_connections(tmp_db, "10.0.0.2", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        logs1 = det.detect()
        assert len(logs1) == 2
        det._alerted.pop(("10.0.0.2", "5.5.5.5", 443), None)
        logs2 = det.detect()
        assert len(logs2) == 1
        assert logs2[0].source_ip == "10.0.0.2"


# ── Kill Chain Entegrasyon Testleri ──────────────────────────────────────────

class TestBeaconingKillChain:
    def test_c2_beaconing_in_stage_map(self):
        from server.attack_chain import STAGE_MAP
        assert "c2_beaconing" in STAGE_MAP
        assert STAGE_MAP["c2_beaconing"] == "lateral"

    def test_c2_beaconing_records_to_kill_chain(self, tmp_db, monkeypatch):
        """Beaconing logu attack chain tracker'a kaydedilince lateral aşaması oluşur."""
        from server.attack_chain import AttackChainTracker
        tracker = AttackChainTracker()
        trigger = tracker.record(
            source_ip="10.0.0.1",
            event_action="c2_beaconing",
        )
        # Tek aşama → tetikleme yok (partial threshold 2)
        assert trigger is None
        # İkinci farklı aşama → PARTIAL_ATTACK_CHAIN
        trigger2 = tracker.record(
            source_ip="10.0.0.1",
            event_action="ssh_failure",  # weaponize
        )
        assert trigger2 is not None
        assert trigger2["chain_type"] == "PARTIAL_ATTACK_CHAIN"

    def test_beaconing_stage_label(self):
        from server.attack_chain import STAGE_MAP, STAGE_LABELS
        stage = STAGE_MAP["c2_beaconing"]
        assert stage in STAGE_LABELS


# ── Entegrasyon: Tam Pipeline ─────────────────────────────────────────────────

class TestBeaconingIntegration:
    def test_empty_db_no_alerts(self, tmp_db, monkeypatch):
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        assert det.detect() == []

    def test_single_connection_no_alert(self, tmp_db, monkeypatch):
        ts = [datetime.now(timezone.utc) - timedelta(minutes=5)]
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, ts)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        assert det.detect() == []

    def test_non_network_events_ignored(self, tmp_db, monkeypatch):
        """network_connection/zeek_connection dışındaki eventler sayılmamalı."""
        base = datetime.now(timezone.utc) - timedelta(minutes=15)
        times = _regular_beacon(base, count=10, interval=60.0)
        _insert_connections(
            tmp_db, "10.0.0.1", "5.5.5.5", 443, times,
            event_action="ssh_failure",
        )
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        assert det.detect() == []

    def test_detector_name(self):
        det = BeaconingDetector()
        assert det.name == "beaconing"

    def test_env_var_defaults(self):
        """Ortam değişkeni yoksa sağlıklı varsayılanlar kullanılmalı."""
        det = BeaconingDetector()
        assert det._window == 1800
        assert det._min_connections == 6
        assert det._min_iat == 30.0
        assert det._max_iat == 300.0
        assert det._jitter == 0.20

    def test_iat_boundary_min(self, tmp_db, monkeypatch):
        """mean_iat tam eşik değerinde (30.0s) → tespit edilmeli."""
        base = datetime.now(timezone.utc) - timedelta(minutes=10)
        times = _regular_beacon(base, count=8, interval=30.0)
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        logs = det.detect()
        assert len(logs) == 1

    def test_iat_boundary_max(self, tmp_db, monkeypatch):
        """mean_iat tam eşik değerinde (300.0s) → tespit edilmeli."""
        base = datetime.now(timezone.utc) - timedelta(hours=1)
        times = _regular_beacon(base, count=8, interval=300.0)
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=7200)
        logs = det.detect()
        assert len(logs) == 1

    def test_identical_timestamps_no_division_error(self, tmp_db, monkeypatch):
        """Tüm timestamp'ler aynıysa ZeroDivisionError olmamalı, alarm üretilmemeli."""
        ts = datetime.now(timezone.utc) - timedelta(minutes=10)
        times = [ts] * 8
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, min_iat=30.0, window_seconds=1800)
        assert det.detect() == []

    def test_unsorted_timestamps_handled(self, tmp_db, monkeypatch):
        """Sırasız timestamp'ler: detect() sıralayarak doğru IAT hesaplamalı."""
        base = datetime.now(timezone.utc) - timedelta(minutes=20)
        times_sorted = _regular_beacon(base, count=8, interval=60.0)
        times_shuffled = times_sorted[4:] + times_sorted[:4]
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, times_shuffled)
        det = _make_detector(tmp_db, monkeypatch, window_seconds=1800)
        logs = det.detect()
        assert len(logs) == 1

    def test_minimum_iat_count_two(self, tmp_db, monkeypatch):
        """Tam min_connections=3 → 2 IAT → Bessel düzeltmesi (N-1=1) ZeroDivisionError yok."""
        base = datetime.now(timezone.utc) - timedelta(minutes=5)
        times = _regular_beacon(base, count=3, interval=60.0)
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, times)
        det = _make_detector(tmp_db, monkeypatch, min_connections=3, window_seconds=1800)
        # 2 IAT, Bessel ile: variance / (N-1=1) = variance — geçerli, alarm üretmeli
        logs = det.detect()
        assert len(logs) == 1


# ── Thread Safety Testleri ────────────────────────────────────────────────────

class TestBeaconingThreadSafety:
    def test_concurrent_detect_no_duplicate_alert(self, tmp_db, monkeypatch):
        """10 paralel thread detect() çağırırsa aynı tuple için tek alarm üretilmeli."""
        from unittest.mock import MagicMock, patch
        base = datetime.now(timezone.utc) - timedelta(minutes=15)
        times = _regular_beacon(base, count=10, interval=60.0)
        _insert_connections(tmp_db, "10.0.0.1", "5.5.5.5", 443, times)

        import server.detectors.beaconing as bmod
        monkeypatch.setattr(bmod, "db", tmp_db)

        det = BeaconingDetector(window_seconds=1800)
        all_results = []
        lock = threading.Lock()
        errors = []

        fake_fp = MagicMock()
        fake_fp.is_suppressed.return_value = False

        def run_detect():
            try:
                with patch("server.fp_manager.fp_manager", fake_fp):
                    results = det.detect()
                with lock:
                    all_results.extend(results)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=run_detect) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(all_results) == 1

    def test_alerted_dict_pruned_after_2x_cooldown(self, tmp_db, monkeypatch):
        """2×cooldown geçmiş girdiler _prune_alerted ile temizlenmeli."""
        import server.detectors.beaconing as bmod
        monkeypatch.setattr(bmod, "db", tmp_db)
        det = BeaconingDetector(window_seconds=60)
        past = datetime.now(timezone.utc) - timedelta(seconds=200)
        with det._lock:
            det._alerted[("10.0.0.1", "5.5.5.5", 443)] = past
            det._alerted[("10.0.0.2", "5.5.5.5", 443)] = datetime.now(timezone.utc)
        det._prune_alerted(datetime.now(timezone.utc))
        with det._lock:
            assert ("10.0.0.1", "5.5.5.5", 443) not in det._alerted
            assert ("10.0.0.2", "5.5.5.5", 443) in det._alerted
