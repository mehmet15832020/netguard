"""
NetGuard — SNMP Trap Receiver

UDP port 162 dinler, gelen TRAP/INFORM paketlerini security_events tablosuna yazar.
Syslog receiver ile aynı asyncio transport/protocol mimarisini kullanır.
"""

import asyncio
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

TRAP_PORT = 162


class SNMPTrapProtocol(asyncio.DatagramProtocol):
    """Gelen SNMP TRAP paketlerini işler."""

    def datagram_received(self, data: bytes, addr: tuple):
        host, port = addr
        try:
            self._handle(data, host)
        except Exception as exc:
            logger.warning(f"SNMP trap işleme hatası ({host}): {exc}")

    def error_received(self, exc: Exception):
        logger.error(f"SNMP trap alım hatası: {exc}")

    def connection_lost(self, exc):
        if exc:
            logger.error(f"SNMP trap bağlantısı kesildi: {exc}")

    @staticmethod
    def _handle(data: bytes, source_ip: str):
        """Trap'i ayrıştır ve DB'ye kaydet."""
        description = _parse_trap(data, source_ip)
        logger.info(f"SNMP TRAP alındı: {source_ip} — {description}")
        try:
            import uuid
            from datetime import datetime, timezone
            from server.database import db
            from shared.models import SecurityEvent, SecurityEventType

            event = SecurityEvent(
                event_id=str(uuid.uuid4()),
                agent_id=source_ip,
                hostname=source_ip,
                event_type=SecurityEventType.SNMP_TRAP,
                severity="info",
                source_ip=source_ip,
                message=description,
                raw_data=data.hex()[:512],
                occurred_at=datetime.now(timezone.utc),
            )
            db.save_security_event(event)
        except Exception as exc:
            logger.error(f"SNMP trap DB yazma hatası: {exc}")


def _parse_trap(data: bytes, source_ip: str) -> str:
    """
    Temel BER ayrıştırma — pysnmp olmadan minimal bilgi çıkar.
    Tam ayrıştırma Faz 7'de pysnmp ile yapılacak.
    """
    try:
        if len(data) < 10:
            return f"Kısa SNMP paketi ({len(data)} byte)"

        # SNMP version: byte 4 (0=v1, 1=v2c, 3=v3)
        version_map = {0: "v1", 1: "v2c", 3: "v3"}
        snmp_version = version_map.get(data[4], "bilinmiyor")

        # PDU type (son birkaç tag'dan)
        pdu_types = {
            0xA0: "GetRequest", 0xA1: "GetNextRequest", 0xA2: "GetResponse",
            0xA3: "SetRequest", 0xA4: "Trap-v1", 0xA5: "GetBulkRequest",
            0xA6: "InformRequest", 0xA7: "Trap-v2",
        }
        pdu_type = "TRAP"
        for byte in data:
            if byte in pdu_types:
                pdu_type = pdu_types[byte]

        return f"SNMP {snmp_version} {pdu_type} from {source_ip} ({len(data)} bytes)"
    except Exception:
        return f"SNMP TRAP from {source_ip} ({len(data)} bytes)"


class SNMPTrapReceiver:
    """UDP 162 portunda SNMP TRAP dinleyicisi."""

    def __init__(self, port: int = TRAP_PORT):
        self._port = port
        self._transport = None

    async def start(self):
        """UDP sunucusunu başlat."""
        loop = asyncio.get_running_loop()
        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                SNMPTrapProtocol,
                local_addr=("0.0.0.0", self._port),
            )
            logger.info(f"SNMP Trap alıcısı başlatıldı (UDP :{self._port})")
        except PermissionError:
            logger.warning(
                f"SNMP Trap alıcısı port {self._port}'i açamadı (root gerekli). "
                "Devre dışı bırakıldı."
            )
        except OSError as exc:
            logger.warning(f"SNMP Trap alıcısı başlatılamadı: {exc}")

    def stop(self):
        if self._transport:
            self._transport.close()
            logger.info("SNMP Trap alıcısı durduruldu.")
