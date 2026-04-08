"""
NetGuard Server — Port Değişim Monitörü

Sistemdeki dinleyen portları periyodik olarak kontrol eder.
Yeni port açılırsa veya mevcut port kapanırsa güvenlik olayı üretir.

Kullanım:
    port_monitor.check(agent_id)  → yeni olaylar varsa liste döner
"""

import logging
import socket
import uuid
from datetime import datetime, timezone
from typing import Optional

import psutil

from shared.models import SecurityEvent, SecurityEventType
from server.database import db

logger = logging.getLogger(__name__)


def _get_listening_ports() -> set[tuple[str, int]]:
    """
    Şu an dinleyen (LISTEN) tüm TCP portlarını döndür.
    Her eleman: (adres, port) çifti.
    """
    ports = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                ports.add((conn.laddr.ip, conn.laddr.port))
    except psutil.AccessDenied:
        logger.warning("Port listesi alınamadı — yetki yetersiz")
    return ports


class PortMonitor:
    """
    Önceki port durumunu hatırlar, değişiklik olduğunda event üretir.
    Server başlatıldığında ilk snapshot'ı alır — baseline olur.
    """

    def __init__(self):
        self._previous: Optional[set[tuple[str, int]]] = None

    def check(self, agent_id: str) -> list[SecurityEvent]:
        """
        Port durumunu kontrol et.
        İlk çağrıda baseline kaydeder, sonrasında değişiklikleri döndürür.
        """
        current = _get_listening_ports()
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)
        events: list[SecurityEvent] = []

        if self._previous is None:
            # İlk çalıştırma — baseline kaydet
            self._previous = current
            logger.info(f"Port baseline alındı: {len(current)} port dinleniyor")
            return []

        opened = current - self._previous
        closed = self._previous - current

        for addr, port in sorted(opened):
            event = SecurityEvent(
                event_id   = str(uuid.uuid4()),
                agent_id   = agent_id,
                hostname   = hostname,
                event_type = SecurityEventType.PORT_OPENED,
                severity   = "warning",
                message    = f"Yeni port açıldı: {addr}:{port}",
                occurred_at= now,
            )
            db.save_security_event(event)
            events.append(event)
            logger.warning(f"PORT AÇILDI: {addr}:{port}")

        for addr, port in sorted(closed):
            event = SecurityEvent(
                event_id   = str(uuid.uuid4()),
                agent_id   = agent_id,
                hostname   = hostname,
                event_type = SecurityEventType.PORT_CLOSED,
                severity   = "info",
                message    = f"Port kapandı: {addr}:{port}",
                occurred_at= now,
            )
            db.save_security_event(event)
            events.append(event)
            logger.info(f"PORT KAPANDI: {addr}:{port}")

        self._previous = current
        return events


# Global instance
port_monitor = PortMonitor()
