"""
NetGuard Server — Storage

Agent kayıt ve anlık metrik snapshot'larını bellekte tutar.
Alert'ler artık doğrudan SQLite'a yazılır/okunur (server/database.py).
Snapshot'lar gerçek zamanlı dashboard için RAM'de, kalıcı metrikler InfluxDB'de.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

from shared.models import AgentRegistration, MetricSnapshot

MAX_SNAPSHOTS_PER_AGENT = 360  # 10 saniyelik aralıkla 1 saatlik veri


@dataclass
class AgentRecord:
    """Bir agent'ın anlık durumunu ve son snapshot'larını tutar."""
    registration: AgentRegistration
    snapshots: deque = field(
        default_factory=lambda: deque(maxlen=MAX_SNAPSHOTS_PER_AGENT)
    )
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class InMemoryStorage:
    """
    Thread-safe agent durum deposu.
    Sadece anlık metrik snapshot'larını ve agent bağlantı durumunu tutar.
    Alert'ler bu sınıfın sorumluluğunda değil — SQLite'a yaz, SQLite'tan oku.
    """

    def __init__(self):
        self._agents: dict[str, AgentRecord] = {}
        self._lock = Lock()

    def register_agent(self, registration: AgentRegistration) -> None:
        with self._lock:
            if registration.agent_id in self._agents:
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
            if snapshot.traffic_summary is None and record.snapshots:
                last = record.snapshots[-1]
                if last.traffic_summary is not None:
                    snapshot.traffic_summary = last.traffic_summary
            record.snapshots.append(snapshot)
            record.last_seen = snapshot.collected_at

    def get_all_agents(self) -> list[AgentRecord]:
        with self._lock:
            return list(self._agents.values())

    def get_agent(self, agent_id: str) -> Optional[AgentRecord]:
        with self._lock:
            return self._agents.get(agent_id)

    def get_latest_snapshot(self, agent_id: str) -> Optional[MetricSnapshot]:
        with self._lock:
            record = self._agents.get(agent_id)
            if record and record.snapshots:
                return record.snapshots[-1]
            return None

    def get_snapshots(self, agent_id: str, limit: int = 60) -> list[MetricSnapshot]:
        with self._lock:
            record = self._agents.get(agent_id)
            if not record:
                return []
            return list(record.snapshots)[-limit:]

    @property
    def agent_count(self) -> int:
        with self._lock:
            return len(self._agents)


storage = InMemoryStorage()