"""
NetGuard — NTP Zaman Doğrulayıcı

İki görevi var:
  1. Sistem saatini NTP sunucusuyla karşılaştır — büyük sapma varsa uyar.
  2. Gelen log timestamp'lerini doğrula — geleceğe veya çok geçmişe ait
     timestamp'ler işaretlenir (log kaynağının saati kaymış olabilir).

Kullanım:
    validator = NTPValidator()
    offset = validator.check_system_clock()   # sistem saati sapması (saniye)
    ok, reason = validator.validate_log_timestamp(ts)  # log ts geçerli mi
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import ntplib

logger = logging.getLogger(__name__)

# Yapılandırma — env ile geçersiz kılınabilir
NTP_SERVER          = os.getenv("NETGUARD_NTP_SERVER", "pool.ntp.org")
NTP_TIMEOUT         = float(os.getenv("NETGUARD_NTP_TIMEOUT", "3"))       # saniye
SYSTEM_CLOCK_WARN   = float(os.getenv("NETGUARD_CLOCK_WARN_SEC", "5"))    # sistem saati uyarı eşiği
SYSTEM_CLOCK_CRIT   = float(os.getenv("NETGUARD_CLOCK_CRIT_SEC", "60"))   # sistem saati kritik eşik
LOG_TS_MAX_PAST_SEC = float(os.getenv("NETGUARD_LOG_TS_MAX_PAST", "3600")) # log max 1 saat geride
LOG_TS_MAX_FUTURE_SEC = float(os.getenv("NETGUARD_LOG_TS_MAX_FUTURE", "60")) # log max 60s ileride


class ClockCheckResult:
    """Sistem saati kontrol sonucu."""

    def __init__(
        self,
        offset_sec: float,
        ntp_server: str,
        checked_at: datetime,
        reachable: bool,
        error: Optional[str] = None,
    ):
        self.offset_sec = offset_sec     # pozitif = sistem ileri, negatif = sistem geri
        self.ntp_server = ntp_server
        self.checked_at = checked_at
        self.reachable  = reachable
        self.error      = error

    @property
    def severity(self) -> str:
        if not self.reachable:
            return "warning"   # NTP'ye ulaşılamazsa uyar ama krit değil
        abs_offset = abs(self.offset_sec)
        if abs_offset >= SYSTEM_CLOCK_CRIT:
            return "critical"
        if abs_offset >= SYSTEM_CLOCK_WARN:
            return "warning"
        return "ok"

    @property
    def is_ok(self) -> bool:
        return self.severity == "ok"

    def __repr__(self) -> str:
        return (
            f"ClockCheckResult(offset={self.offset_sec:+.3f}s, "
            f"severity={self.severity}, reachable={self.reachable})"
        )


class NTPValidator:
    """NTP tabanlı zaman doğrulayıcı."""

    def __init__(
        self,
        ntp_server: str = NTP_SERVER,
        timeout: float = NTP_TIMEOUT,
    ):
        self._ntp_server = ntp_server
        self._timeout    = timeout
        self._client     = ntplib.NTPClient()
        self._last_result: Optional[ClockCheckResult] = None

    # ------------------------------------------------------------------ #
    #  Sistem saati kontrolü
    # ------------------------------------------------------------------ #

    def check_system_clock(self) -> ClockCheckResult:
        """
        NTP sunucusuna sorgu at, sistem saatinin sapmasını hesapla.
        Ağa erişilemezse reachable=False döner — uygulama çalışmaya devam eder.
        """
        now = datetime.now(timezone.utc)
        try:
            response = self._client.request(
                self._ntp_server,
                version=3,
                timeout=self._timeout,
            )
            offset = response.offset   # saniye cinsinden sapma
            result = ClockCheckResult(
                offset_sec = offset,
                ntp_server = self._ntp_server,
                checked_at = now,
                reachable  = True,
            )
        except ntplib.NTPException as exc:
            result = ClockCheckResult(
                offset_sec = 0.0,
                ntp_server = self._ntp_server,
                checked_at = now,
                reachable  = False,
                error      = f"NTP protocol hatası: {exc}",
            )
        except Exception as exc:
            result = ClockCheckResult(
                offset_sec = 0.0,
                ntp_server = self._ntp_server,
                checked_at = now,
                reachable  = False,
                error      = f"NTP erişim hatası: {exc}",
            )

        self._last_result = result
        self._log_result(result)
        return result

    def _log_result(self, result: ClockCheckResult) -> None:
        if not result.reachable:
            logger.warning(f"NTP sunucusuna ulaşılamadı ({self._ntp_server}): {result.error}")
            return
        if result.severity == "critical":
            logger.critical(
                f"Sistem saati kritik sapma: {result.offset_sec:+.3f}s "
                f"(eşik: ±{SYSTEM_CLOCK_CRIT}s) — NTP: {self._ntp_server}"
            )
        elif result.severity == "warning":
            logger.warning(
                f"Sistem saati sapması: {result.offset_sec:+.3f}s "
                f"(eşik: ±{SYSTEM_CLOCK_WARN}s) — NTP: {self._ntp_server}"
            )
        else:
            logger.debug(f"Sistem saati senkronize: {result.offset_sec:+.3f}s")

    @property
    def last_result(self) -> Optional[ClockCheckResult]:
        """Son kontrol sonucu — henüz kontrol yapılmadıysa None."""
        return self._last_result

    # ------------------------------------------------------------------ #
    #  Log timestamp doğrulama
    # ------------------------------------------------------------------ #

    def validate_log_timestamp(self, ts: datetime) -> tuple[bool, str]:
        """
        Log timestamp'inin makul aralıkta olup olmadığını kontrol et.

        Döner: (geçerli_mi, açıklama)
        - (True,  "ok")                      — timestamp normal
        - (False, "too_far_in_past: ...")    — çok eski
        - (False, "too_far_in_future: ...")  — geleceğe ait
        """
        # Timezone farkından kaçınmak için her ikisini UTC'ye çevir
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = (ts - now).total_seconds()

        if delta < -LOG_TS_MAX_PAST_SEC:
            return False, f"too_far_in_past: {abs(delta):.0f}s geride"

        if delta > LOG_TS_MAX_FUTURE_SEC:
            return False, f"too_far_in_future: {delta:.0f}s ileride"

        return True, "ok"


# ------------------------------------------------------------------ #
#  Global instance
# ------------------------------------------------------------------ #

ntp_validator = NTPValidator()
