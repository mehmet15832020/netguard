"""
NetGuard — NTP Validator testleri

NTP sunucusuna gerçek bağlantı açmadan (mock ile) test edilir.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from server.ntp_validator import NTPValidator, ClockCheckResult, SYSTEM_CLOCK_WARN, SYSTEM_CLOCK_CRIT


# ------------------------------------------------------------------ #
#  ClockCheckResult severity testi
# ------------------------------------------------------------------ #

class TestClockCheckResult:
    def test_ok_when_offset_small(self):
        r = ClockCheckResult(offset_sec=1.0, ntp_server="pool.ntp.org",
                             checked_at=datetime.now(timezone.utc), reachable=True)
        assert r.severity == "ok"
        assert r.is_ok

    def test_warning_when_offset_over_warn_threshold(self):
        r = ClockCheckResult(offset_sec=SYSTEM_CLOCK_WARN + 1,
                             ntp_server="pool.ntp.org",
                             checked_at=datetime.now(timezone.utc), reachable=True)
        assert r.severity == "warning"

    def test_critical_when_offset_over_crit_threshold(self):
        r = ClockCheckResult(offset_sec=SYSTEM_CLOCK_CRIT + 1,
                             ntp_server="pool.ntp.org",
                             checked_at=datetime.now(timezone.utc), reachable=True)
        assert r.severity == "critical"

    def test_warning_when_unreachable(self):
        r = ClockCheckResult(offset_sec=0.0, ntp_server="pool.ntp.org",
                             checked_at=datetime.now(timezone.utc), reachable=False,
                             error="timeout")
        assert r.severity == "warning"
        assert not r.is_ok

    def test_negative_offset_also_triggers_warning(self):
        r = ClockCheckResult(offset_sec=-(SYSTEM_CLOCK_WARN + 1),
                             ntp_server="pool.ntp.org",
                             checked_at=datetime.now(timezone.utc), reachable=True)
        assert r.severity == "warning"


# ------------------------------------------------------------------ #
#  Sistem saati kontrolü (NTP mock)
# ------------------------------------------------------------------ #

class TestCheckSystemClock:
    def _make_ntp_response(self, offset: float):
        """Sahte NTP yanıtı üret."""
        mock = MagicMock()
        mock.offset = offset
        return mock

    def test_ok_result_on_small_offset(self):
        validator = NTPValidator()
        with patch.object(validator._client, "request",
                          return_value=self._make_ntp_response(0.5)):
            result = validator.check_system_clock()
        assert result.reachable
        assert result.offset_sec == pytest.approx(0.5)
        assert result.is_ok

    def test_warning_result_on_large_offset(self):
        validator = NTPValidator()
        with patch.object(validator._client, "request",
                          return_value=self._make_ntp_response(30.0)):
            result = validator.check_system_clock()
        assert result.severity == "warning"

    def test_critical_result_on_very_large_offset(self):
        validator = NTPValidator()
        with patch.object(validator._client, "request",
                          return_value=self._make_ntp_response(120.0)):
            result = validator.check_system_clock()
        assert result.severity == "critical"

    def test_unreachable_when_exception(self):
        validator = NTPValidator()
        with patch.object(validator._client, "request",
                          side_effect=Exception("network unreachable")):
            result = validator.check_system_clock()
        assert not result.reachable
        assert "network unreachable" in result.error

    def test_last_result_updated(self):
        validator = NTPValidator()
        assert validator.last_result is None
        with patch.object(validator._client, "request",
                          return_value=self._make_ntp_response(1.0)):
            validator.check_system_clock()
        assert validator.last_result is not None


# ------------------------------------------------------------------ #
#  Log timestamp doğrulama
# ------------------------------------------------------------------ #

class TestValidateLogTimestamp:
    def setup_method(self):
        self.validator = NTPValidator()

    def test_current_timestamp_is_valid(self):
        ts = datetime.now(timezone.utc)
        ok, reason = self.validator.validate_log_timestamp(ts)
        assert ok
        assert reason == "ok"

    def test_recent_past_is_valid(self):
        ts = datetime.now(timezone.utc) - timedelta(minutes=30)
        ok, reason = self.validator.validate_log_timestamp(ts)
        assert ok

    def test_too_old_timestamp_rejected(self):
        ts = datetime.now(timezone.utc) - timedelta(hours=2)
        ok, reason = self.validator.validate_log_timestamp(ts)
        assert not ok
        assert "too_far_in_past" in reason

    def test_future_timestamp_rejected(self):
        ts = datetime.now(timezone.utc) + timedelta(minutes=5)
        ok, reason = self.validator.validate_log_timestamp(ts)
        assert not ok
        assert "too_far_in_future" in reason

    def test_slightly_future_is_ok(self):
        # 10 saniye ileride — kabul edilmeli
        ts = datetime.now(timezone.utc) + timedelta(seconds=10)
        ok, reason = self.validator.validate_log_timestamp(ts)
        assert ok

    def test_naive_datetime_handled(self):
        # timezone bilgisi olmayan datetime de çalışmalı
        ts = datetime.utcnow()  # naive
        ok, reason = self.validator.validate_log_timestamp(ts)
        assert ok


# ------------------------------------------------------------------ #
#  Normalizer entegrasyonu — timestamp anomalisi tag'e yansır
# ------------------------------------------------------------------ #

class TestNTPIntegrationInNormalizer:
    def test_old_timestamp_gets_anomaly_tag(self):
        """Çok eski timestamp'li log normalize edilince tag eklenir."""
        from server.log_normalizer import normalize

        # Çok eski timestamp içeren auth.log satırı oluştur
        # (Yıl 2020 — kesinlikle geçmişte)
        raw = "Jan  1 00:00:00 myhost sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
        norm = normalize(raw, source_host="myhost")
        # Parse başarılı olmalı (auth.log formatı doğru)
        assert norm is not None
        # Timestamp 2020 yılı olarak yorumlanır — anomali tag'i bekliyoruz
        anomaly_tags = [t for t in norm.tags if "timestamp_anomaly" in t]
        assert len(anomaly_tags) > 0
