"""
NetGuard — Dedektör taban sınıfı

Her dedektör bu sınıftan türer ve detect() metodunu uygular.
detect() → şüpheli ham olayları NormalizedLog olarak döner.
Bu loglar log_normalizer üzerinden DB'ye yazılır,
korelasyon motoru eşiği aşılınca CorrelatedEvent üretir.
"""

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from shared.models import LogCategory, LogSourceType, NormalizedLog

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """Tüm dedektörlerin ata sınıfı."""

    name: str = "base"
    observer_hostname: str = "localhost"

    @abstractmethod
    def detect(self) -> list[NormalizedLog]:
        """
        Tespiti çalıştır.
        Şüpheli olay varsa NormalizedLog listesi döner, yoksa boş liste.
        """
        ...

    def _make_log(
        self,
        event_action: str,
        message: str,
        event_category: LogCategory,
        severity: str = "warning",
        source_ip: str = None,
        destination_ip: str = None,
        source_port: int = None,
        destination_port: int = None,
        network_protocol: str = None,
        tags: list = None,
    ) -> NormalizedLog:
        """NormalizedLog üretmek için kısa yardımcı."""
        return NormalizedLog(
            log_id      = str(uuid.uuid4()),
            raw_id      = str(uuid.uuid4()),
            source_type = LogSourceType.NETGUARD,
            observer_hostname = self.observer_hostname,
            timestamp   = datetime.now(timezone.utc),
            severity    = severity,
            event_category    = event_category,
            event_action  = event_action,
            source_ip      = source_ip,
            destination_ip      = destination_ip,
            source_port    = source_port,
            destination_port    = destination_port,
            network_protocol    = network_protocol,
            message     = message,
            tags        = tags or [self.name],
        )
