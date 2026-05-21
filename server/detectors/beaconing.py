"""
NetGuard — C2 Beaconing Dedektörü

MITRE ATT&CK T1071 (Application Layer Protocol) ve T1571 (Non-Standard Port).
Cobalt Strike varsayılan 60s beacon, APT1 5dk ±%10-15 jitter gibi kalıpları yakalar.

Algoritma:
  normalized_logs'tan son WINDOW saniyedeki network_connection kayıtları alınır.
  (src_ip, dst_ip, dst_port) üçlüsüne göre gruplandırılır.
  Her grup için inter-arrival time (IAT) istatistikleri hesaplanır:
    mean_iat : bağlantı aralığı ortalaması
    jitter   : sample stddev / mean (Bessel düzeltmeli — N-1)
  Kriter: min 6 bağlantı · 30 ≤ mean_iat ≤ 300 saniye · jitter < 0.20

Referanslar:
  MITRE ATT&CK T1071, T1571, TA0011 (Command and Control)
  Cobalt Strike: Malcolm Levy, "Detecting Cobalt Strike Beacon Traffic", 2021
  APT1: Mandiant APT1 Report, 2013 — 5 dakika ±%10-15 jitter
  RITA: BlackHat 2018 "Real Intelligence Threat Analytics" — IAT + Bessel CV
  CIS Controls v8.1 Safeguard 13.6 — network traffic monitoring
"""

import ipaddress
import logging
import math
import os
import socket
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from server.database import db
from server.detectors.base import BaseDetector
from shared.models import LogCategory, NormalizedLog

logger = logging.getLogger(__name__)

BEACON_WINDOW_SECONDS   = int(os.getenv("NETGUARD_BEACON_WINDOW",   "1800"))
BEACON_MIN_CONNECTIONS  = int(os.getenv("NETGUARD_BEACON_MIN_CONN",  "6"))
BEACON_MIN_IAT          = float(os.getenv("NETGUARD_BEACON_MIN_IAT",  "30.0"))
BEACON_MAX_IAT          = float(os.getenv("NETGUARD_BEACON_MAX_IAT",  "300.0"))
BEACON_JITTER_THRESHOLD = float(os.getenv("NETGUARD_BEACON_JITTER",  "0.20"))
_ALERTED_MAX_ENTRIES    = 10_000

_CONN_ACTIONS = ("network_connection", "zeek_connection")


def _validate_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


class BeaconingDetector(BaseDetector):
    """
    C2 beacon tespiti: normalized_logs'taki ağ bağlantı kayıtlarını
    IAT istatistikleri ile analiz eder (MITRE ATT&CK TA0011 — C2).

    _alerted sözlüğü thread-safe (threading.Lock); stale girdiler her
    detect() çağrısında 2×cooldown sınırıyla budanır (max 10 000 giriş).
    """

    name = "beaconing"

    def __init__(
        self,
        window_seconds: int = BEACON_WINDOW_SECONDS,
        min_connections: int = BEACON_MIN_CONNECTIONS,
        min_iat: float = BEACON_MIN_IAT,
        max_iat: float = BEACON_MAX_IAT,
        jitter_threshold: float = BEACON_JITTER_THRESHOLD,
    ):
        self._window = window_seconds
        self._min_connections = min_connections
        self._min_iat = min_iat
        self._max_iat = max_iat
        self._jitter = jitter_threshold
        self._alerted: dict[tuple, datetime] = {}
        self._lock = threading.Lock()
        try:
            self.observer_hostname = socket.gethostname()
        except (OSError, socket.error):
            self.observer_hostname = "localhost"

    # ── public ────────────────────────────────────────────────────────────────

    def detect(self) -> list[NormalizedLog]:
        now = datetime.now(timezone.utc)
        since = now - timedelta(seconds=self._window)
        since_iso = since.isoformat()

        self._prune_alerted(now)

        try:
            rows = self._query_connections(since_iso)
        except Exception as exc:
            logger.error("BeaconingDetector DB sorgusu başarısız: %s", exc)
            return []

        groups: dict[tuple, list[datetime]] = defaultdict(list)
        for row in rows:
            src   = row.get("source_ip")
            dst   = row.get("destination_ip")
            dport = row.get("destination_port")
            ts    = row.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except ValueError:
                    continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            groups[(src, dst, int(dport))].append(ts)

        results = []
        cooldown = timedelta(seconds=self._window)

        for (src_ip, dst_ip, dst_port), timestamps in groups.items():
            if not (_validate_ip(src_ip) and _validate_ip(dst_ip)):
                continue
            if len(timestamps) < self._min_connections:
                continue

            timestamps.sort()
            iats = [
                (timestamps[i + 1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]
            if len(iats) < 2:
                continue

            mean_iat = sum(iats) / len(iats)
            if not (self._min_iat <= mean_iat <= self._max_iat):
                continue

            # Bessel düzeltmeli sample stddev (N-1) — BlackHat 2018 RITA yaklaşımı
            variance = sum((x - mean_iat) ** 2 for x in iats) / (len(iats) - 1)
            stddev = math.sqrt(variance)
            jitter_ratio = stddev / mean_iat if mean_iat > 0 else 1.0
            if jitter_ratio >= self._jitter:
                continue

            key = (src_ip, dst_ip, dst_port)
            with self._lock:
                last_alert = self._alerted.get(key)
                if last_alert and (now - last_alert) < cooldown:
                    continue
                self._alerted[key] = now

            from server.fp_manager import fp_manager
            if fp_manager.is_suppressed("c2_beaconing", source_ip=src_ip, tenant_id="default"):
                continue

            log = self._make_log(
                event_action="c2_beaconing",
                message=(
                    f"C2 Beaconing: {src_ip} → {dst_ip}:{dst_port} "
                    f"| {len(timestamps)} conn / {self._window}s "
                    f"| mean_iat={mean_iat:.1f}s jitter={jitter_ratio:.2%} "
                    f"[MITRE ATT&CK T1071]"
                ),
                event_category=LogCategory.NETWORK,
                severity="high",
                source_ip=src_ip,
                destination_ip=dst_ip,
                destination_port=dst_port,
                tags=["c2_beaconing", "mitre_t1071"],
            )
            results.append(log)
            logger.warning(
                "C2 BEACONING: %s → %s:%d | mean_iat=%.1fs jitter=%.2f conn=%d",
                src_ip, dst_ip, dst_port, mean_iat, jitter_ratio, len(timestamps),
            )

        return results

    def reset_alerted(self) -> None:
        with self._lock:
            self._alerted.clear()

    # ── private ───────────────────────────────────────────────────────────────

    def _prune_alerted(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=2 * self._window)
        with self._lock:
            stale = [k for k, v in self._alerted.items() if v < cutoff]
            for k in stale:
                del self._alerted[k]
            if len(self._alerted) > _ALERTED_MAX_ENTRIES:
                oldest = sorted(self._alerted.items(), key=lambda x: x[1])
                for k, _ in oldest[: len(self._alerted) - _ALERTED_MAX_ENTRIES]:
                    del self._alerted[k]

    def _query_connections(self, since_iso: str) -> list[dict]:
        placeholders = ", ".join("%s" for _ in _CONN_ACTIONS)
        with db._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT source_ip, destination_ip, destination_port, timestamp
                FROM normalized_logs
                WHERE event_action IN ({placeholders})
                  AND timestamp >= %s
                  AND source_ip IS NOT NULL
                  AND destination_ip IS NOT NULL
                  AND destination_port IS NOT NULL
                ORDER BY source_ip, destination_ip, destination_port, timestamp
                """,
                (*_CONN_ACTIONS, since_iso),
            ).fetchall()
        return [dict(r) for r in rows]


beaconing_detector = BeaconingDetector()
