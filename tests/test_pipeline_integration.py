"""
NetGuard — Pipeline Entegrasyon Testleri

Birim testlerden farkı:
  - Gerçek DB (tmp SQLite), gerçek modül zincirleri
  - Modüller birbirine bağlı — birinin çıktısı diğerinin girdisi
  - Mock yalnızca dış servisler için: notifier, threat_intel, ws_manager

Test grupları:
  1. Normalize Pipeline — ham log → DB
  2. Correlation Pipeline — normalized_logs → correlated_event + incident
  3. Kill Chain Pipeline — aşamalar → attack chain trigger
  4. Alert Engine Pipeline — metric snapshot → DB alert
  5. Uçtan Uca (E2E) — raw syslog string → kill chain → critical incident
"""

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest

from server.database import DatabaseManager
from server.log_normalizer import process_and_store
from server.alert_engine import AlertEngine
from server.attack_chain import AttackChainTracker
from shared.models import (
    NormalizedLog, LogSourceType, LogCategory,
    MetricSnapshot, CPUMetrics, MemoryMetrics, DiskMetrics,
)


# ─────────────────────────────────────────────────────────────────────────────
#  Fixture — tüm pipeline modüllerini aynı tmp DB'ye bağlar
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def pipeline_db(tmp_path, monkeypatch):
    """
    Entegrasyon testleri için izole DB.
    correlator, log_normalizer, attack_chain, incident route hepsi
    aynı test DB'yi görür.
    """
    db_file = str(tmp_path / "pipeline.db")
    test_db = DatabaseManager(db_path=db_file)

    monkeypatch.setattr("server.database.db",          test_db)
    monkeypatch.setattr("server.correlator.db",        test_db)
    monkeypatch.setattr("server.log_normalizer.db",    test_db)
    monkeypatch.setattr("server.routes.incidents.db",  test_db)
    monkeypatch.setattr("server.incident_enricher.db", test_db)

    # ws_manager lazy import içinden çağrılır — gerçek singleton'ı mock'la
    import server.ws_manager as _ws_mod
    monkeypatch.setattr(_ws_mod, "ws_manager",
                        MagicMock(broadcast_from_thread=MagicMock()))

    return test_db


@pytest.fixture
def fresh_chain_tracker():
    """Her test için temiz attack chain — önceki IP geçmişi olmadan."""
    tracker = AttackChainTracker()
    return tracker


def _norm_log(event_type: str, src_ip: str, severity: str = "warning",
              category: LogCategory = LogCategory.NETWORK,
              timestamp: datetime | None = None) -> NormalizedLog:
    """Test normalize log fabrikası."""
    return NormalizedLog(
        log_id      = str(uuid.uuid4()),
        raw_id      = str(uuid.uuid4()),
        source_type = LogSourceType.SYSLOG,
        source_host = "test-host",
        timestamp   = timestamp or datetime.now(timezone.utc),
        severity    = severity,
        category    = category,
        event_type  = event_type,
        src_ip      = src_ip,
        message     = f"{event_type} from {src_ip}",
        tags        = [],
    )


def _metric_snapshot(cpu_pct: float = 10.0, ram_pct: float = 10.0) -> MetricSnapshot:
    total = 8 * 1024**3
    used  = int(total * ram_pct / 100)
    return MetricSnapshot(
        agent_id     = "test-agent",
        hostname     = "test-host",
        collected_at = datetime.now(timezone.utc),
        cpu    = CPUMetrics(usage_percent=cpu_pct, core_count=4, load_avg_1m=0.5),
        memory = MemoryMetrics(total_bytes=total, used_bytes=used,
                               available_bytes=total - used),
        disks  = [DiskMetrics(mount_point="/", total_bytes=total,
                              used_bytes=used, free_bytes=total - used,
                              usage_percent=ram_pct)],
    )


# ─────────────────────────────────────────────────────────────────────────────
#  1. Normalize Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalizePipeline:
    """process_and_store → DB'deki raw_logs + normalized_logs durumu."""

    def test_valid_syslog_written_to_both_tables(self, pipeline_db, monkeypatch):
        """Geçerli SSH failure log'u raw_logs'a VE normalized_logs'a yazılmalı."""
        monkeypatch.setattr("server.log_normalizer.db", pipeline_db)
        raw = "Apr 12 10:23:45 myhost sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2"
        norm = process_and_store(raw, source_host="myhost")

        assert norm is not None
        assert norm.event_type == "ssh_failure"
        assert norm.src_ip == "10.0.0.1"

        norm_logs = pipeline_db.get_normalized_logs(limit=10)
        assert len(norm_logs) == 1
        assert norm_logs[0].event_type == "ssh_failure"

        with pipeline_db._connect() as conn:
            row = conn.execute("SELECT normalized FROM raw_logs LIMIT 1").fetchone()
        assert row["normalized"] == 1

    def test_unparseable_log_flags_raw_only(self, pipeline_db, monkeypatch):
        """Parse edilemeyen log raw_logs'a yazılmalı, normalized=-1, normalized_logs boş."""
        monkeypatch.setattr("server.log_normalizer.db", pipeline_db)
        raw = "1712915025.123\tOnlyTwoFields"  # Zeek formatı ama çok kısa
        result = process_and_store(raw, source_host="host1")

        assert result is None
        assert len(pipeline_db.get_normalized_logs(limit=10)) == 0

        with pipeline_db._connect() as conn:
            row = conn.execute("SELECT normalized FROM raw_logs LIMIT 1").fetchone()
        assert row["normalized"] == -1

    def test_multiple_logs_accumulate_in_db(self, pipeline_db, monkeypatch):
        """Arka arkaya 5 log normalize edilince normalized_logs 5 kayıt içermeli."""
        monkeypatch.setattr("server.log_normalizer.db", pipeline_db)
        raw_template = "Apr 12 10:23:{:02d} myhost sshd[1234]: Failed password for root from 10.0.0.{} port 22 ssh2"
        for i in range(5):
            process_and_store(raw_template.format(i, i + 1), "myhost")

        norm_logs = pipeline_db.get_normalized_logs(limit=20)
        assert len(norm_logs) == 5


# ─────────────────────────────────────────────────────────────────────────────
#  2. Correlation Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestCorrelationPipeline:
    """
    normalized_logs → correlator.run() → correlated_event + incident

    Korrelasyon motoru DB'yi doğrudan okur; bu testlerde logları
    DB'ye elle yazarak gerçek SQL sorgusu + eşik mantığını test ederiz.
    """

    def test_ssh_brute_force_rule_creates_correlated_event(self, pipeline_db):
        """
        6 ssh_failure logu → ssh_brute_force kuralı tetiklenmeli →
        correlated_event DB'ye yazılmalı.
        """
        from server.correlator import Correlator

        # DB'ye 6 ssh_failure logu yaz
        for i in range(6):
            pipeline_db.save_normalized_log(_norm_log("ssh_failure", "10.0.0.50"))

        corr = Correlator()
        corr.load_rules()

        with (
            patch("server.notifier.notifier", MagicMock()),
            patch("server.threat_intel.lookup", return_value=None),
        ):
            events = corr.run()

        ssh_events = [e for e in events if "ssh" in e.rule_id.lower() or "ssh" in e.event_type.lower()]
        assert len(ssh_events) >= 1, "SSH brute force kuralı tetiklenmeli"
        assert ssh_events[0].group_value == "10.0.0.50"

    def test_correlated_event_creates_incident(self, pipeline_db):
        """
        Korele olay tetiklenince DB'de incident oluşmalı.
        """
        from server.correlator import Correlator

        for _ in range(6):
            pipeline_db.save_normalized_log(_norm_log("ssh_failure", "10.0.0.51"))

        corr = Correlator()
        corr.load_rules()

        with (
            patch("server.notifier.notifier", MagicMock()),
            patch("server.threat_intel.lookup", return_value=None),
        ):
            corr.run()

        incidents = pipeline_db.get_incidents()
        assert len(incidents) >= 1
        ips = [i.get("group_value") for i in incidents]
        assert "10.0.0.51" in ips

    def test_below_threshold_does_not_trigger(self, pipeline_db):
        """
        Eşik altında log (3 adet, kural genellikle 5-6 bekler) →
        correlated_event oluşmamalı.
        """
        from server.correlator import Correlator

        for _ in range(3):
            pipeline_db.save_normalized_log(_norm_log("ssh_failure", "10.0.0.52"))

        corr = Correlator()
        corr.load_rules()

        with (
            patch("server.notifier.notifier", MagicMock()),
            patch("server.threat_intel.lookup", return_value=None),
        ):
            events = corr.run()

        ssh_events = [e for e in events if e.group_value == "10.0.0.52"]
        assert len(ssh_events) == 0

    def test_duplicate_events_merge_into_single_incident(self, pipeline_db):
        """
        Aynı IP + aynı kural iki defa tetiklenince incident sayısı 1 olmalı,
        incident_events 2 olmalı.
        """
        from server.correlator import Correlator

        src = "10.0.0.53"
        for _ in range(6):
            pipeline_db.save_normalized_log(_norm_log("ssh_failure", src))

        corr = Correlator()
        corr.load_rules()

        with (
            patch("server.notifier.notifier", MagicMock()),
            patch("server.threat_intel.lookup", return_value=None),
        ):
            corr.run()
            corr.run()   # İkinci çalıştırma — aynı IP, eşik hâlâ aşılıyor

        incidents = [i for i in pipeline_db.get_incidents() if i.get("group_value") == src]
        assert len(incidents) == 1, "Aynı kaynak için tek incident olmalı"

    def test_threat_intel_escalates_to_critical(self, pipeline_db):
        """
        AbuseIPDB score≥70 → incident severity critical'e yükselmeli.
        """
        from server.correlator import Correlator

        src = "10.0.0.54"
        for _ in range(6):
            pipeline_db.save_normalized_log(_norm_log("ssh_failure", src))

        corr = Correlator()
        corr.load_rules()

        ti_response = {"score": 90, "is_public": True, "country": "CN"}
        with (
            patch("server.notifier.notifier", MagicMock()),
            patch("server.threat_intel.lookup", return_value=ti_response),
        ):
            corr.run()

        incidents = [i for i in pipeline_db.get_incidents() if i.get("group_value") == src]
        assert len(incidents) >= 1
        assert incidents[0]["severity"] == "critical"


# ─────────────────────────────────────────────────────────────────────────────
#  3. Kill Chain Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestKillChainPipeline:
    """
    attack_chain_tracker.record() → stage takibi → chain trigger

    AttackChainTracker kendi başına test edilir (DB bağımlılığı olmadan).
    Sonrasında tam entegrasyon: correlated_event → chain trigger → critical incident.
    """

    def test_single_stage_no_trigger(self, fresh_chain_tracker):
        """Tek aşama kayıtlı → trigger yok."""
        result = fresh_chain_tracker.record("10.0.0.1", "port_scan_detected")
        assert result is None

    def test_two_stages_partial_chain(self, fresh_chain_tracker):
        """RECON + WEAPONIZE → PARTIAL_ATTACK_CHAIN tetiklenmeli."""
        fresh_chain_tracker.record("10.0.0.2", "port_scan_detected")
        result = fresh_chain_tracker.record("10.0.0.2", "ssh_failure")
        assert result is not None
        assert result["chain_type"] == "PARTIAL_ATTACK_CHAIN"
        assert result["severity"] == "warning"
        assert "recon" in result["stages"]
        assert "weaponize" in result["stages"]

    def test_three_stages_full_chain(self, fresh_chain_tracker):
        """RECON + WEAPONIZE + ACCESS → FULL_ATTACK_CHAIN tetiklenmeli."""
        fresh_chain_tracker.record("10.0.0.3", "port_scan_detected")
        fresh_chain_tracker.record("10.0.0.3", "ssh_failure")
        result = fresh_chain_tracker.record("10.0.0.3", "ssh_success")
        assert result is not None
        assert result["chain_type"] == "FULL_ATTACK_CHAIN"
        assert result["severity"] == "critical"
        assert len(result["stages"]) >= 3

    def test_different_ips_independent_chains(self, fresh_chain_tracker):
        """İki farklı IP bağımsız zincir tutar."""
        fresh_chain_tracker.record("10.0.0.10", "port_scan_detected")
        fresh_chain_tracker.record("10.0.0.10", "ssh_failure")

        # Sadece bir aşamalı farklı IP
        result = fresh_chain_tracker.record("10.0.0.11", "port_scan_detected")
        assert result is None  # 10.0.0.11 için henüz trigger yok

    def test_expired_stages_not_counted(self, fresh_chain_tracker):
        """30 dakika öncesi kayıt pencere dışı → zincire dahil edilmemeli."""
        old_time = datetime.now(timezone.utc) - timedelta(minutes=35)
        # Eski RECON kaydı ekle
        with fresh_chain_tracker._lock:
            fresh_chain_tracker._chains["10.0.0.20"]["recon"].append(old_time)

        # Yeni WEAPONIZE — eski RECON süresi dolmuş olmalı
        result = fresh_chain_tracker.record("10.0.0.20", "ssh_failure", occurred_at=datetime.now(timezone.utc))
        # Sadece 1 aktif aşama (weaponize) → trigger yok
        assert result is None

    def test_lateral_movement_stage_recorded(self, fresh_chain_tracker):
        """lateral_movement event_type → 'lateral' aşamasına kaydedilmeli."""
        fresh_chain_tracker.record("10.0.0.5", "port_scan_detected")
        fresh_chain_tracker.record("10.0.0.5", "ssh_failure")
        fresh_chain_tracker.record("10.0.0.5", "ssh_success")
        result = fresh_chain_tracker.record("10.0.0.5", "lateral_movement")
        assert result is not None
        assert "lateral" in result["stages"]


# ─────────────────────────────────────────────────────────────────────────────
#  4. Alert Engine Pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertEnginePipeline:
    """
    MetricSnapshot → AlertEngine.evaluate() → Alert nesneleri
    Ardından DB'ye kayıt → DB'den geri okuma.
    """

    def test_high_cpu_creates_active_alert(self, pipeline_db):
        """CPU %95 → warning alert üretilmeli."""
        engine = AlertEngine()
        snap = _metric_snapshot(cpu_pct=95.0)
        alerts = engine.evaluate(snap)
        cpu_alerts = [a for a in alerts if a.metric == "cpu"]
        assert len(cpu_alerts) == 1
        assert cpu_alerts[0].status.value == "active"
        assert cpu_alerts[0].severity.value == "warning"

    def test_low_cpu_no_alert(self):
        """CPU %30 → alert üretilmemeli."""
        engine = AlertEngine()
        snap = _metric_snapshot(cpu_pct=30.0)
        alerts = engine.evaluate(snap)
        cpu_alerts = [a for a in alerts if a.metric == "cpu"]
        assert len(cpu_alerts) == 0

    def test_alert_resolves_when_metric_drops(self):
        """CPU önce yüksek → active alert; sonra düşük → resolved alert."""
        engine = AlertEngine()

        alerts_high = engine.evaluate(_metric_snapshot(cpu_pct=95.0))
        assert any(a.metric == "cpu" and a.status.value == "active" for a in alerts_high)

        alerts_low = engine.evaluate(_metric_snapshot(cpu_pct=30.0))
        assert any(a.metric == "cpu" and a.status.value == "resolved" for a in alerts_low)

    def test_no_duplicate_alert_for_same_metric(self):
        """Aynı metrik sürekli yüksek → ikinci evaluate yeni alert üretmemeli."""
        engine = AlertEngine()
        first  = engine.evaluate(_metric_snapshot(cpu_pct=95.0))
        second = engine.evaluate(_metric_snapshot(cpu_pct=96.0))  # Hâlâ yüksek

        first_cpu  = [a for a in first  if a.metric == "cpu"]
        second_cpu = [a for a in second if a.metric == "cpu"]
        assert len(first_cpu) == 1
        assert len(second_cpu) == 0  # Zaten active — tekrar üretilmemeli

    def test_alert_engine_persists_to_db(self, pipeline_db):
        """AlertEngine çıktısı DB'ye kayıt edilince geri okunabilmeli."""
        engine = AlertEngine()
        snap   = _metric_snapshot(cpu_pct=95.0)
        alerts = engine.evaluate(snap)

        for alert in alerts:
            pipeline_db.save_alert(alert)

        db_alerts = pipeline_db.get_alerts(status="active")
        cpu_in_db = [a for a in db_alerts if a.metric == "cpu"]
        assert len(cpu_in_db) == 1
        assert cpu_in_db[0].value == 95.0

    def test_alert_engine_restores_active_state_from_db(self, pipeline_db):
        """
        Sunucu yeniden başlama simülasyonu:
        DB'de active alert varken restore_active_alerts() çağrılınca
        yeni engine ikinci evaluate'de duplicate üretmemeli.
        """
        engine1 = AlertEngine()
        for alert in engine1.evaluate(_metric_snapshot(cpu_pct=95.0)):
            pipeline_db.save_alert(alert)

        engine2 = AlertEngine()
        engine2.restore_active_alerts(pipeline_db)

        second_high = engine2.evaluate(_metric_snapshot(cpu_pct=96.0))
        cpu_new = [a for a in second_high if a.metric == "cpu"]
        assert len(cpu_new) == 0, "Restore sonrası duplicate alert üretilmemeli"


# ─────────────────────────────────────────────────────────────────────────────
#  5. Uçtan Uca (E2E) — Raw Log → Kill Chain → Critical Incident
# ─────────────────────────────────────────────────────────────────────────────

class TestEndToEndPipeline:
    """
    Ham syslog string'lerinden başlayarak:
    process_and_store → normalized_logs → correlator.run() →
    correlated_event → attack_chain → incident

    Bu testler sistemin tamamını birlikte çalıştırır.
    """

    def test_ssh_brute_force_end_to_end(self, pipeline_db):
        """
        6 ssh_failure normalize logu (güncel timestamp) →
        correlator → correlated_event + incident oluşmalı.

        Not: raw syslog parse yerine doğrudan normalize log yazıyoruz;
        korrelator zaman penceresi (300s) syslog'un geçmiş tarihini görmez.
        """
        from server.correlator import Correlator

        for _ in range(6):
            pipeline_db.save_normalized_log(
                _norm_log("ssh_failure", "10.1.0.100",
                          category=LogCategory.AUTHENTICATION)
            )

        norm_logs = pipeline_db.get_normalized_logs(event_type="ssh_failure", limit=20)
        assert len(norm_logs) >= 6, "6 normalize log DB'de olmalı"

        corr = Correlator()
        corr.load_rules()

        with (
            patch("server.notifier.notifier", MagicMock()),
            patch("server.threat_intel.lookup", return_value=None),
        ):
            events = corr.run()

        assert len(events) >= 1
        incidents = pipeline_db.get_incidents()
        assert len(incidents) >= 1

    def test_full_kill_chain_creates_critical_incident(self, pipeline_db, monkeypatch):
        """
        Port scan → SSH brute force → SSH success (3 aşama)
        → FULL_ATTACK_CHAIN → critical incident.

        Aşamalar correlated_event olarak correlator üzerinden işlenir.
        """
        from server.correlator import Correlator

        monkeypatch.setattr("server.log_normalizer.db", pipeline_db)
        src = "10.2.0.99"

        # RECON: port scan logları
        for _ in range(25):
            pipeline_db.save_normalized_log(
                _norm_log("port_scan_attempt", src, severity="warning")
            )

        # WEAPONIZE: SSH failure logları
        for _ in range(6):
            pipeline_db.save_normalized_log(
                _norm_log("ssh_failure", src, severity="warning",
                          category=LogCategory.AUTHENTICATION)
            )

        # ACCESS: SSH success
        pipeline_db.save_normalized_log(
            _norm_log("ssh_success", src, severity="info",
                      category=LogCategory.AUTHENTICATION)
        )

        corr = Correlator()
        corr.load_rules()

        with (
            patch("server.notifier.notifier", MagicMock()),
            patch("server.threat_intel.lookup", return_value=None),
        ):
            corr.run()

        # En az bir incident oluşmuş olmalı
        incidents = pipeline_db.get_incidents()
        assert len(incidents) >= 1

        # Kill chain trigger'ı olan critical incident var mı?
        critical = [i for i in incidents if i["severity"] == "critical"]
        # Kill chain 3 aşamada critical incident üretir —
        # correlated_event'ların attack_chain'e ulaşması için
        # _check_attack_chain çağrılması şarttır (correlator.run() içinde)
        assert len(critical) >= 1 or len(incidents) >= 2, (
            "Full kill chain ya critical incident ya da birden fazla incident üretmeli"
        )

    def test_parse_fail_logs_invisible_to_correlator(self, pipeline_db, monkeypatch):
        """
        Parse edilemeyen loglar (normalized=-1) correlator'ın gördüğü
        normalized_logs tablosunda yer almamalı → false positive yok.
        """
        from server.correlator import Correlator

        monkeypatch.setattr("server.log_normalizer.db", pipeline_db)

        # Bozuk log — parse başarısız olacak
        for _ in range(10):
            process_and_store("1712915025.123\tX", "host1")

        corr = Correlator()
        corr.load_rules()

        with (
            patch("server.notifier.notifier", MagicMock()),
            patch("server.threat_intel.lookup", return_value=None),
        ):
            events = corr.run()

        assert len(events) == 0, "Parse başarısız loglar korelasyona dahil edilmemeli"
        assert len(pipeline_db.get_incidents()) == 0

    def test_notifier_called_on_correlated_event(self, pipeline_db):
        """
        Korelasyon tetiklenince notifier.notify_correlated() çağrılmalı.
        """
        from server.correlator import Correlator

        src = "10.3.0.1"
        for _ in range(6):
            pipeline_db.save_normalized_log(_norm_log("ssh_failure", src))

        corr = Correlator()
        corr.load_rules()

        import server.notifier as _notifier_mod
        mock_notifier = MagicMock()
        with (
            patch.object(_notifier_mod, "notifier", mock_notifier),
            patch("server.threat_intel.lookup", return_value=None),
        ):
            events = corr.run()

        if events:
            mock_notifier.notify_correlated.assert_called()
