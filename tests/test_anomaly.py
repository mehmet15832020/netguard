"""Anomaly detection modülü testleri."""

import math
import os
import tempfile
from datetime import datetime, timezone

import pytest

from server.anomaly.baseline import BaselineStore
from server.anomaly.collector import MetricsCollector
from server.anomaly.detector import StatisticalDetector
from server.anomaly.engine import AnomalyEngine
from server.anomaly.models import (
    AnomalyResult,
    BaselinePoint,
    MetricSnapshot,
    METRICS,
    _Z_WARN,
)
from server.anomaly.store import AnomalyResultStore


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "test_anomaly.db")


@pytest.fixture
def baseline_store(tmp_db):
    return BaselineStore(tmp_db)


@pytest.fixture
def result_store(tmp_db):
    return AnomalyResultStore(tmp_db)


@pytest.fixture
def engine(tmp_db):
    return AnomalyEngine(tmp_db)


# ── BaselinePoint: Welford algoritması ────────────────────────────────────────

class TestBaselinePoint:
    def test_initial_state(self):
        bp = BaselinePoint("1.2.3.4", "conn_rate", 14)
        assert bp.mean == 0.0
        assert bp.std == 0.0
        assert bp.sample_count == 0
        assert not bp.is_warmed_up

    def test_single_update(self):
        bp = BaselinePoint("1.2.3.4", "conn_rate", 14)
        bp.update(10.0)
        assert bp.mean == 10.0
        assert bp.sample_count == 1

    def test_mean_converges(self):
        bp = BaselinePoint("1.2.3.4", "conn_rate", 14)
        for v in [10.0] * 100:
            bp.update(v)
        assert abs(bp.mean - 10.0) < 1e-9
        assert bp.std < 1e-6

    def test_variance_welford_accuracy(self):
        bp = BaselinePoint("1.2.3.4", "conn_rate", 14)
        values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        for v in values:
            bp.update(v)
        assert abs(bp.mean - 5.0) < 1e-9
        assert abs(bp.variance - 4.571428) < 0.0001

    def test_warmed_up_threshold(self):
        bp = BaselinePoint("1.2.3.4", "conn_rate", 14)
        for i in range(19):
            bp.update(float(i))
        assert not bp.is_warmed_up
        bp.update(19.0)
        assert bp.is_warmed_up

    def test_z_score_zero_std(self):
        bp = BaselinePoint("1.2.3.4", "conn_rate", 14)
        bp.update(5.0)
        assert bp.z_score(5.0) == 0.0

    def test_z_score_positive(self):
        bp = BaselinePoint("1.2.3.4", "conn_rate", 14)
        for _ in range(30):
            bp.update(10.0)
        bp.m2 = 30.0  # std ≈ 1.0
        bp.sample_count = 31
        z = bp.z_score(13.0)
        assert z > 0

    def test_last_updated_set(self):
        bp = BaselinePoint("1.2.3.4", "conn_rate", 14)
        assert bp.last_updated is None
        bp.update(1.0)
        assert bp.last_updated is not None


# ── BaselineStore ──────────────────────────────────────────────────────────────

class TestBaselineStore:
    def test_get_nonexistent_returns_none(self, baseline_store):
        assert baseline_store.get("1.2.3.4", "conn_rate", 14) is None

    def test_get_or_create_returns_default(self, baseline_store):
        bp = baseline_store.get_or_create("1.2.3.4", "conn_rate", 14)
        assert bp.entity_id == "1.2.3.4"
        assert bp.sample_count == 0

    def test_save_and_retrieve(self, baseline_store):
        bp = BaselinePoint("1.2.3.4", "conn_rate", 14)
        for v in [5.0, 10.0, 15.0]:
            bp.update(v)
        baseline_store.save(bp)

        loaded = baseline_store.get("1.2.3.4", "conn_rate", 14)
        assert loaded is not None
        assert abs(loaded.mean - bp.mean) < 1e-9
        assert loaded.sample_count == 3

    def test_upsert_updates_existing(self, baseline_store):
        bp = baseline_store.get_or_create("1.2.3.4", "conn_rate", 14)
        bp.update(5.0)
        baseline_store.save(bp)
        bp.update(10.0)
        baseline_store.save(bp)

        loaded = baseline_store.get("1.2.3.4", "conn_rate", 14)
        assert loaded.sample_count == 2

    def test_list_entities_empty(self, baseline_store):
        assert baseline_store.list_entities() == []

    def test_list_entities_populated(self, baseline_store):
        for ip in ["1.2.3.4", "5.6.7.8"]:
            bp = BaselinePoint(ip, "conn_rate", 14)
            bp.update(5.0)
            baseline_store.save(bp)
        entities = baseline_store.list_entities()
        assert len(entities) == 2

    def test_warmup_status_not_warmed(self, baseline_store):
        bp = BaselinePoint("1.2.3.4", "conn_rate", 14)
        bp.update(1.0)
        baseline_store.save(bp)
        status = baseline_store.warmup_status("1.2.3.4")
        assert not status["warmed_up"]
        assert status["sample_count"] == 1

    def test_warmup_status_warmed(self, baseline_store):
        for metric in METRICS:
            bp = BaselinePoint("1.2.3.4", metric, 14)
            for _ in range(25):
                bp.update(5.0)
            baseline_store.save(bp)
        status = baseline_store.warmup_status("1.2.3.4")
        assert status["warmed_up"]
        assert status["progress_pct"] == 100


# ── AnomalyResult ──────────────────────────────────────────────────────────────

class TestAnomalyResult:
    def _warmed_bp(self) -> BaselinePoint:
        bp = BaselinePoint("1.2.3.4", "conn_rate", 14)
        for _ in range(30):
            bp.update(10.0)
        bp.m2 = 29.0   # std ≈ 1.0
        return bp

    def test_warning_severity(self):
        bp = self._warmed_bp()
        result = AnomalyResult.from_baseline(bp, 12.6, 2.6)
        assert result.severity == "warning"
        assert result.confidence == 0.60

    def test_high_severity(self):
        bp = self._warmed_bp()
        result = AnomalyResult.from_baseline(bp, 14.0, 4.0)
        assert result.severity == "high"
        assert result.confidence == 0.80

    def test_critical_severity(self):
        bp = self._warmed_bp()
        result = AnomalyResult.from_baseline(bp, 16.0, 5.0)
        assert result.severity == "critical"
        assert result.confidence == 0.95

    def test_message_contains_entity(self):
        bp = self._warmed_bp()
        result = AnomalyResult.from_baseline(bp, 12.6, 2.6)
        assert "1.2.3.4" in result.message
        assert "conn_rate" in result.message

    def test_result_id_is_uuid(self):
        bp = self._warmed_bp()
        result = AnomalyResult.from_baseline(bp, 12.6, 2.6)
        import uuid
        uuid.UUID(result.result_id)   # raises if invalid


# ── StatisticalDetector ────────────────────────────────────────────────────────

class TestStatisticalDetector:
    def _snap(self, **overrides) -> MetricSnapshot:
        defaults = {
            "entity_id":         "1.2.3.4",
            "window_start":      datetime.now(timezone.utc),
            "fw_block_rate":     0.0,
            "conn_rate":         5.0,
            "unique_dst_ips":    3.0,
            "unique_dst_ports":  3.0,
            "auth_failure_rate": 0.0,
        }
        defaults.update(overrides)
        return MetricSnapshot(**defaults)

    def _warmed_baselines(self, mean=10.0, std_m2_ratio=30.0) -> dict[str, BaselinePoint]:
        bps = {}
        for m in METRICS:
            bp = BaselinePoint("1.2.3.4", m, 14)
            for _ in range(30):
                bp.update(mean)
            bp.m2 = std_m2_ratio   # std ≈ 1.0
            bps[m] = bp
        return bps

    def test_no_anomaly_normal_traffic(self):
        det = StatisticalDetector()
        snap = self._snap(conn_rate=10.5)
        bps = self._warmed_baselines()
        results = det.detect(snap, bps)
        assert results == []

    def test_detects_high_conn_rate(self):
        det = StatisticalDetector()
        # conn_rate mean=10, std≈1, observed=14 → z≈4
        bps = self._warmed_baselines(mean=10.0, std_m2_ratio=29.0)
        snap = self._snap(conn_rate=14.0)
        results = det.detect(snap, bps)
        assert any(r.metric == "conn_rate" for r in results)

    def test_skips_unwarmed_baselines(self):
        det = StatisticalDetector()
        snap = self._snap(conn_rate=999.0)
        bps = {m: BaselinePoint("1.2.3.4", m, 14) for m in METRICS}
        results = det.detect(snap, bps)
        assert results == []

    def test_skips_below_min_threshold(self):
        det = StatisticalDetector()
        bps = self._warmed_baselines(mean=0.1, std_m2_ratio=0.01)
        snap = self._snap(fw_block_rate=1.5)   # < min threshold 2.0
        results = det.detect(snap, bps)
        fw_results = [r for r in results if r.metric == "fw_block_rate"]
        assert fw_results == []


# ── AnomalyResultStore ─────────────────────────────────────────────────────────

class TestAnomalyResultStore:
    def _result(self, entity_id="1.2.3.4", severity="warning") -> AnomalyResult:
        bp = BaselinePoint(entity_id, "conn_rate", 14)
        for _ in range(25):
            bp.update(10.0)
        bp.m2 = 24.0
        return AnomalyResult.from_baseline(bp, 13.0, 3.0)

    def test_save_and_list(self, result_store):
        r = self._result()
        result_store.save(r)
        results = result_store.list_recent(limit=10)
        assert len(results) == 1
        assert results[0]["entity_id"] == "1.2.3.4"

    def test_duplicate_ignored(self, result_store):
        r = self._result()
        result_store.save(r)
        result_store.save(r)
        assert len(result_store.list_recent()) == 1

    def test_filter_by_entity(self, result_store):
        result_store.save(self._result("1.2.3.4"))
        result_store.save(self._result("5.6.7.8"))
        results = result_store.list_recent(entity_id="1.2.3.4")
        assert len(results) == 1

    def test_summary(self, result_store):
        result_store.save(self._result(severity="warning"))
        result_store.save(self._result("5.6.7.8", severity="critical"))
        summary = result_store.summary()
        assert summary["total"] == 2
        assert summary["affected_entities"] == 2


# ── AnomalyEngine ──────────────────────────────────────────────────────────────

class TestAnomalyEngine:
    def test_engine_initializes(self, engine):
        assert engine is not None

    def test_get_baselines_empty(self, engine):
        assert engine.get_baselines() == []

    def test_get_summary_empty(self, engine):
        summary = engine.get_summary()
        assert summary.get("total") == 0

    def test_warmup_status_unknown_entity(self, engine):
        status = engine.get_warmup_status("9.9.9.9")
        assert not status["warmed_up"]

    def test_cycle_empty_db(self, engine):
        engine._cycle()   # boş DB'de çalışmalı, hata vermemeli
        assert engine._cycle_count == 1

    def test_cycle_writes_normalized_log_on_anomaly(self, tmp_db, monkeypatch):
        import sqlite3
        engine = AnomalyEngine(tmp_db)

        snap = MetricSnapshot(
            entity_id="1.2.3.4",
            window_start=datetime.now(timezone.utc),
            fw_block_rate=0.0,
            conn_rate=999.0,
            unique_dst_ips=0.0,
            unique_dst_ports=0.0,
            auth_failure_rate=0.0,
        )
        monkeypatch.setattr(engine._collector, "collect", lambda: [snap])

        for metric in METRICS:
            bp = BaselinePoint("1.2.3.4", metric, datetime.now(timezone.utc).hour)
            for _ in range(30):
                bp.update(10.0)
            bp.m2 = 29.0
            engine._baselines.save(bp)

        import server.notifier as notifier_module
        monkeypatch.setattr(notifier_module.notifier, "notify_anomaly", lambda r: None)

        engine._cycle()

        with sqlite3.connect(tmp_db) as conn:
            row = conn.execute(
                "SELECT event_type, src_ip FROM normalized_logs WHERE event_type='anomaly_detected'"
            ).fetchone()
        assert row is not None
        assert row[1] == "1.2.3.4"
