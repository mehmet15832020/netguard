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
    source_host: str = "localhost"

    @abstractmethod
    def detect(self) -> list[NormalizedLog]:
        """
        Tespiti çalıştır.
        Şüpheli olay varsa NormalizedLog listesi döner, yoksa boş liste.
        """
        ...

    def _make_log(
        self,
        event_type: str,
        message: str,
        category: LogCategory,
        severity: str = "warning",
        src_ip: str = None,
        dst_ip: str = None,
        src_port: int = None,
        dst_port: int = None,
        tags: list = None,
    ) -> NormalizedLog:
        """NormalizedLog üretmek için kısa yardımcı."""
        return NormalizedLog(
            log_id      = str(uuid.uuid4()),
            raw_id      = str(uuid.uuid4()),
            source_type = LogSourceType.NETGUARD,
            source_host = self.source_host,
            timestamp   = datetime.now(timezone.utc),
            severity    = severity,
            category    = category,
            event_type  = event_type,
            src_ip      = src_ip,
            dst_ip      = dst_ip,
            src_port    = src_port,
            dst_port    = dst_port,
            message     = message,
            tags        = tags or [self.name],
        )
