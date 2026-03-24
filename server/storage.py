"""
NetGuard Server — Storage

Şu an: Veriyi bellekte (RAM) tutar.
İleride: Bu sınıfın arayüzü değişmeden InfluxDB backend'e geçilecek.

Maksimum kaç snapshot saklanacağı sabittir — bellek taşmaz.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

from shared.models import AgentRegistration, MetricSnapshot
from shared.models import AgentRegistration, Alert, AlertStatus, MetricSnapshot

# Agent başına tutulacak maksimum snapshot sayısı
MAX_SNAPSHOTS_PER_AGENT = 360  # 10 saniyelik aralıkla 1 saatlik veri


@dataclass
class AgentRecord:
    """Bir agent'ın tüm bilgilerini tutar."""
    registration: AgentRegistration
    snapshots: deque = field(
        default_factory=lambda: deque(maxlen=MAX_SNAPSHOTS_PER_AGENT)
    )
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class InMemoryStorage:
    """
    Thread-safe bellek içi depolama.
    Lock kullanıyoruz çünkü FastAPI async — aynı anda birden fazla
    agent veri gönderebilir.
    """

    def __init__(self):
        self._agents: dict[str, AgentRecord] = {}
        self._alerts: list[Alert] = []    # ← bunu ekle
        self._lock = Lock()

    def register_agent(self, registration: AgentRegistration) -> None:
        """Agent'ı kaydet. Zaten varsa kaydını güncelle."""
        with self._lock:
            if registration.agent_id in self._agents:
                # Mevcut snapshot'ları koru, sadece kaydı güncelle
                self._agents[registration.agent_id].registration = registration
                self._agents[registration.agent_id].last_seen = datetime.now(timezone.utc)
            else:
                self._agents[registration.agent_id] = AgentRecord(
                    registration=registration
                )

    def store_snapshot(self, snapshot: MetricSnapshot) -> None:
        with self._lock:
            if snapshot.agent_id not in self._agents:
                self._agents[snapshot.agent_id] = AgentRecord(
                    registration=AgentRegistration(
                        agent_id=snapshot.agent_id,
                        hostname=snapshot.hostname,
                        os_name="unknown",
                        os_version="unknown",
                        python_version="unknown",
                    )
                )
            record = self._agents[snapshot.agent_id]
            
            # Traffic summary varsa sakla, yoksa öncekini koru
            if snapshot.traffic_summary is None and record.snapshots:
                last = record.snapshots[-1]
                if last.traffic_summary is not None:
                    snapshot.traffic_summary = last.traffic_summary
            
            record.snapshots.append(snapshot)
            record.last_seen = snapshot.collected_at

    def get_all_agents(self) -> list[AgentRecord]:
        """Tüm kayıtlı agent'ları döndür."""
        with self._lock:
            return list(self._agents.values())

    def get_agent(self, agent_id: str) -> Optional[AgentRecord]:
        """Belirli bir agent'ı döndür. Yoksa None."""
        with self._lock:
            return self._agents.get(agent_id)

    def get_latest_snapshot(self, agent_id: str) -> Optional[MetricSnapshot]:
        """Agent'ın en son snapshot'ını döndür."""
        with self._lock:
            record = self._agents.get(agent_id)
            if record and record.snapshots:
                return record.snapshots[-1]
            return None

    def get_snapshots(
        self, agent_id: str, limit: int = 60
    ) -> list[MetricSnapshot]:
        """Agent'ın son N snapshot'ını döndür."""
        with self._lock:
            record = self._agents.get(agent_id)
            if not record:
                return []
            snapshots = list(record.snapshots)
            return snapshots[-limit:]


    def store_alert(self, alert: Alert) -> None:
        """Alert'i kaydet veya güncelle."""
        with self._lock:
            if alert.status == AlertStatus.RESOLVED:
                # Mevcut alert'i resolve et
                for existing in self._alerts:
                    if existing.alert_id == alert.alert_id:
                        existing.status = AlertStatus.RESOLVED
                        existing.resolved_at = alert.resolved_at
                        return
            else:
                self._alerts.append(alert)

    def get_alerts(
        self,
        status: Optional[str] = None,
        limit: int = 100
    ) -> list[Alert]:
        """Alert listesini döndür. Status filtresi opsiyonel."""
        with self._lock:
            alerts = list(self._alerts)
            if status:
                alerts = [a for a in alerts if a.status == status]
            # En yeni önce
            alerts.sort(key=lambda a: a.triggered_at, reverse=True)
            return alerts[:limit]

    @property
    def agent_count(self) -> int:
        with self._lock:
            return len(self._agents)


# Global storage instance — uygulama boyunca tek bir tane
storage = InMemoryStorage()