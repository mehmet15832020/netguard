"""
NetGuard Alert Engine

Her snapshot geldiğinde kurallara göre kontrol yapar.
Alert oluşturur, çözüldüğünde resolve eder.

Kural eklemek için sadece _RULES listesine yeni kural ekle.
Mevcut kodu değiştirmek gerekmez.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable

from shared.models import Alert, AlertSeverity, AlertStatus, MetricSnapshot

if TYPE_CHECKING:
    from server.database import DatabaseManager

logger = logging.getLogger(__name__)


@dataclass
class AlertRule:
    """
    Tek bir alert kuralı.
    check_fn: snapshot alır, (tetiklendi mi, değer, eşik) döner.
    """
    rule_id: str
    metric: str
    severity: AlertSeverity
    message_template: str          # "{value:.1f}% > {threshold}%" gibi
    check_fn: Callable[[MetricSnapshot], tuple[bool, float, float]]


def _cpu_check(snapshot: MetricSnapshot) -> tuple[bool, float, float]:
    threshold = 80.0
    value = snapshot.cpu.usage_percent
    return value > threshold, value, threshold


def _ram_check(snapshot: MetricSnapshot) -> tuple[bool, float, float]:
    threshold = 85.0
    mem = snapshot.memory
    value = (mem.used_bytes / mem.total_bytes * 100) if mem.total_bytes > 0 else 0
    return value > threshold, value, threshold


def _disk_check(snapshot: MetricSnapshot) -> tuple[bool, float, float]:
    threshold = 90.0
    root = next((d for d in snapshot.disks if d.mount_point == "/"), None)
    if root is None:
        return False, 0.0, threshold
    return root.usage_percent > threshold, root.usage_percent, threshold

def _bandwidth_check(snapshot: MetricSnapshot) -> tuple[bool, float, float]:
    """Toplam inbound trafik 100 Mbps'i geçerse alert."""
    threshold = 100.0  # Mbps
    if not snapshot.network_snapshot:
        return False, 0.0, threshold
    total_mbps = sum(
        b.bytes_recv_per_sec / 1_000_000
        for b in snapshot.network_snapshot.bandwidth
        if b.interface_name not in ("lo",)
    )
    return total_mbps > threshold, round(total_mbps, 2), threshold

def _suspicious_traffic_check(snapshot: MetricSnapshot) -> tuple[bool, float, float]:
    threshold = 10.0
    if not snapshot.traffic_summary:
        return False, 0.0, threshold
    value = float(snapshot.traffic_summary.suspicious_packet_count)
    return value > threshold, value, threshold

# Tüm aktif kurallar — yeni kural eklemek için buraya ekle
_RULES: list[AlertRule] = [
    AlertRule(
        rule_id="cpu_high",
        metric="cpu",
        severity=AlertSeverity.WARNING,
        message_template="CPU kullanımı yüksek: {value:.1f}% (eşik: {threshold:.0f}%)",
        check_fn=_cpu_check,
    ),
    AlertRule(
        rule_id="ram_high",
        metric="memory",
        severity=AlertSeverity.WARNING,
        message_template="RAM kullanımı yüksek: {value:.1f}% (eşik: {threshold:.0f}%)",
        check_fn=_ram_check,
    ),
    AlertRule(
        rule_id="disk_high",
        metric="disk",
        severity=AlertSeverity.CRITICAL,
        message_template="Disk dolmak üzere: {value:.1f}% (eşik: {threshold:.0f}%)",
        check_fn=_disk_check,
    ),
    AlertRule(
        rule_id="bandwidth_high",
        metric="network",
        severity=AlertSeverity.WARNING,
        message_template="Yüksek ağ trafiği: {value:.1f} Mbps (eşik: {threshold:.0f} Mbps)",
        check_fn=_bandwidth_check,
    ),
    AlertRule(
        rule_id="suspicious_traffic",
        metric="traffic",
        severity=AlertSeverity.CRITICAL,
        message_template="Şüpheli trafik tespit edildi: {value:.0f} paket (eşik: {threshold:.0f})",
        check_fn=_suspicious_traffic_check,
    ),
]


class AlertEngine:
    """
    Alert Engine ana sınıfı.
    Alert listesini döndürür; çağıran katman SQLite'a yazar.
    """

    def __init__(self):
        # "agent_id:metric" → alert_id  (aktif alert takibi)
        self._active: dict[str, str] = {}

    def restore_active_alerts(self, db: "DatabaseManager") -> None:
        """Sunucu yeniden başladığında aktif alert'leri DB'den yükler.
        Bu olmadan restart sonrası aynı alert tekrar üretilir."""
        alerts = db.get_alerts(status="active")
        for alert in alerts:
            if alert.agent_id == "correlator":
                continue
            key = f"{alert.agent_id}:{alert.metric}"
            self._active[key] = alert.alert_id
        if alerts:
            logger.info(f"AlertEngine: {len(self._active)} aktif alert DB'den yüklendi")

    def evaluate(self, snapshot: MetricSnapshot) -> list[Alert]:
        """
        Snapshot'ı tüm kurallara göre değerlendir.
        Yeni alert veya resolve listesi döndür.
        """
        results: list[Alert] = []
        now = datetime.now(timezone.utc)

        for rule in _RULES:
            key = f"{snapshot.agent_id}:{rule.metric}"
            triggered, value, threshold = rule.check_fn(snapshot)

            if triggered and key not in self._active:
                # Yeni alert oluştur
                alert = Alert(
                    alert_id=str(uuid.uuid4()),
                    agent_id=snapshot.agent_id,
                    hostname=snapshot.hostname,
                    severity=rule.severity,
                    status=AlertStatus.ACTIVE,
                    metric=rule.metric,
                    message=rule.message_template.format(
                        value=value, threshold=threshold
                    ),
                    value=round(value, 2),
                    threshold=threshold,
                    triggered_at=now,
                )
                self._active[key] = alert.alert_id
                logger.warning(
                    f"ALERT [{rule.severity.upper()}] "
                    f"{snapshot.hostname}: {alert.message}"
                )
                results.append(alert)

            elif not triggered and key in self._active:
                # Alert çözüldü — resolve et
                alert_id = self._active.pop(key)
                results.append(
                    Alert(
                        alert_id=alert_id,
                        agent_id=snapshot.agent_id,
                        hostname=snapshot.hostname,
                        severity=rule.severity,
                        status=AlertStatus.RESOLVED,
                        metric=rule.metric,
                        message=f"Çözüldü: {rule.metric}",
                        value=round(value, 2),
                        threshold=threshold,
                        triggered_at=now,
                        resolved_at=now,
                    )
                )
                logger.info(
                    f"RESOLVED {snapshot.hostname}: {rule.metric}"
                )

        return results


# Global instance
alert_engine = AlertEngine()