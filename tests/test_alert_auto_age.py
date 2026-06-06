"""Alert auto-age ve yeni risk skoru formülü testleri.

QRadar/Splunk TTL pattern: 24 saatten eski aktif alertler otomatik çözülür.
Risk skoru log-scale, incident-centric, son 6 saatteki alertlere dayalı.

Kaynak: QRadar Offense Management §4.2, Splunk ES Risk Framework, Darktrace score
"""

import math
import uuid
from datetime import datetime, timedelta, timezone

import pytest


def _now():
    return datetime.now(timezone.utc)


def _insert_alert(conn, tenant_id: str = "default", severity: str = "critical",
                  hours_ago: float = 0) -> str:
    alert_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    triggered_at = _now() - timedelta(hours=hours_ago)
    conn.execute(
        """
        INSERT INTO alerts
            (alert_id, agent_id, hostname, severity, status, metric, message,
             value, threshold, triggered_at, tenant_id)
        VALUES (%s, %s, 'host', %s, 'active', 'cpu', 'msg', 1.0, 80.0, %s, %s)
        """,
        [alert_id, agent_id, severity, triggered_at, tenant_id],
    )
    return alert_id


# ─── auto_age_alerts ─────────────────────────────────────────────────────────

class TestAutoAgeAlerts:

    def test_old_alerts_resolved(self, tmp_db):
        """24 saatten eski aktif alertler çözüldü durumuna geçer."""
        with tmp_db._connect() as conn:
            old_id = _insert_alert(conn, hours_ago=25)
            _insert_alert(conn, hours_ago=25)

        count = tmp_db.auto_age_alerts(older_than_hours=24)
        assert count == 2

        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT status FROM alerts WHERE alert_id = %s", [old_id]
            ).fetchone()
        assert row["status"] == "resolved"

    def test_recent_alerts_untouched(self, tmp_db):
        """Son 6 saatteki alertler auto-age etkilenmez."""
        with tmp_db._connect() as conn:
            _insert_alert(conn, hours_ago=3)
            _insert_alert(conn, hours_ago=5)

        count = tmp_db.auto_age_alerts(older_than_hours=24)
        assert count == 0

    def test_boundary_exactly_at_threshold(self, tmp_db):
        """Tam eşikte olan alert: 24h → çözülür, 23h 59m → kalır."""
        with tmp_db._connect() as conn:
            _insert_alert(conn, hours_ago=24.1)
            _insert_alert(conn, hours_ago=23.9)

        count = tmp_db.auto_age_alerts(older_than_hours=24)
        assert count == 1

    def test_already_resolved_not_affected(self, tmp_db):
        """Zaten çözülmüş alertler etkilenmez."""
        with tmp_db._connect() as conn:
            alert_id = _insert_alert(conn, hours_ago=30)
            conn.execute(
                "UPDATE alerts SET status='resolved' WHERE alert_id=%s", [alert_id]
            )

        count = tmp_db.auto_age_alerts(older_than_hours=24)
        assert count == 0

    def test_tenant_filter_respected(self, tmp_db):
        """Tenant filtresi: yalnızca belirtilen tenant'ın alertleri yaşlandırılır."""
        with tmp_db._connect() as conn:
            _insert_alert(conn, tenant_id="tenant_a", hours_ago=30)
            _insert_alert(conn, tenant_id="tenant_b", hours_ago=30)

        count = tmp_db.auto_age_alerts(older_than_hours=24, tenant_id="tenant_a")
        assert count == 1

    def test_resolved_at_set(self, tmp_db):
        """auto_age resolved_at timestamp'ı doldurur."""
        with tmp_db._connect() as conn:
            alert_id = _insert_alert(conn, hours_ago=30)

        tmp_db.auto_age_alerts(older_than_hours=24)

        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT resolved_at FROM alerts WHERE alert_id=%s", [alert_id]
            ).fetchone()
        assert row["resolved_at"] is not None


# ─── count_active_alerts_since ────────────────────────────────────────────────

class TestCountActiveAlertsSince:

    def test_counts_by_severity(self, tmp_db):
        """Son N saatteki aktif alertleri severity'ye göre sayar."""
        with tmp_db._connect() as conn:
            _insert_alert(conn, severity="critical", hours_ago=2)
            _insert_alert(conn, severity="critical", hours_ago=3)
            _insert_alert(conn, severity="warning",  hours_ago=1)
            _insert_alert(conn, severity="critical", hours_ago=10)  # dışarıda

        result = tmp_db.count_active_alerts_since(hours=6)
        assert result["critical"] == 2
        assert result["warning"]  == 1

    def test_excludes_old_alerts(self, tmp_db):
        """Pencere dışındaki alertler sayılmaz."""
        with tmp_db._connect() as conn:
            _insert_alert(conn, hours_ago=30)

        result = tmp_db.count_active_alerts_since(hours=6)
        assert result["critical"] == 0

    def test_empty_returns_zeros(self, tmp_db):
        """Alert yoksa tüm sayılar 0 döner."""
        result = tmp_db.count_active_alerts_since(hours=6)
        assert result == {"critical": 0, "high": 0, "warning": 0, "info": 0}


# ─── Risk Skoru Formülü ───────────────────────────────────────────────────────

class TestRiskScoreFormula:
    """Log-scale formülün doğruluğunu doğrular — reports.py mantığını yansıtır."""

    def _score(self, recent_critical=0, open_inc=0, inv_inc=0, high_plus=0, anomaly_high=0):
        inc_score  = min(50, (open_inc + inv_inc) * 12)
        crit_score = min(30, int(math.log1p(recent_critical) * 8))
        corr_score = min(15, int(math.log1p(high_plus) * 3))
        anom_score = min(10, anomaly_high * 2)
        return min(100, inc_score + crit_score + corr_score + anom_score)

    def test_zero_inputs_zero_score(self):
        assert self._score() == 0

    def test_single_critical_alert(self):
        """1 kritik alert düşük puan üretir."""
        score = self._score(recent_critical=1)
        assert 0 < score <= 20

    def test_high_alert_count_caps_at_30(self):
        """Kritik alert bileşeni max 30 puan."""
        score_many = self._score(recent_critical=1000)
        assert score_many <= 30

    def test_incidents_dominate_score(self):
        """Açık incident'lar skoru en çok etkiler (max 50 pt)."""
        score_inc  = self._score(open_inc=4)
        score_crit = self._score(recent_critical=1000)
        assert score_inc > score_crit

    def test_lab_data_not_max_score(self):
        """Lab koşulları (196 crit, 2336 high+, 11 anomali, 0 incident) max 100 üretmez."""
        score = self._score(recent_critical=30, open_inc=0, high_plus=2336, anomaly_high=11)
        assert score < 100

    def test_status_thresholds(self):
        """Skor bantları doğru statüsle eşleşir."""
        def status(score):
            if score == 0:       return "safe"
            elif score <= 25:    return "low"
            elif score <= 55:    return "warning"
            elif score <= 80:    return "elevated"
            else:                return "danger"

        assert status(0)   == "safe"
        assert status(15)  == "low"
        assert status(40)  == "warning"
        assert status(70)  == "elevated"
        assert status(90)  == "danger"
