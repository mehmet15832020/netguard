"""
NetGuard — Syslog Receiver

UDP 5140 portunu dinler (root gerektirmeyen standart dışı port).
Gelen her syslog mesajını log_normalizer üzerinden işler.

Başlatmak için:
    receiver = SyslogReceiver()
    await receiver.start()
"""

import asyncio
import logging
import os

from server.log_normalizer import process_and_store

logger = logging.getLogger(__name__)

SYSLOG_HOST = os.getenv("NETGUARD_SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT = int(os.getenv("NETGUARD_SYSLOG_PORT", "5140"))


class _SyslogProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protokolü — her gelen datagram bir log mesajı."""

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        source_host = addr[0]
        try:
            raw_content = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return

        if not raw_content:
            return

        try:
            process_and_store(raw_content, source_host)
        except Exception as exc:
            logger.error(f"Syslog işleme hatası ({source_host}): {exc}")

    def error_received(self, exc: Exception) -> None:
        logger.error(f"Syslog UDP hatası: {exc}")

    def connection_lost(self, exc: Exception) -> None:
        if exc:
            logger.warning(f"Syslog bağlantısı kesildi: {exc}")


class SyslogReceiver:
    """UDP syslog alıcısı."""

    def __init__(
        self,
        host: str = SYSLOG_HOST,
        port: int = SYSLOG_PORT,
    ):
        self._host = host
        self._port = port
        self._transport = None

    async def start(self) -> None:
        """UDP dinlemeyi başlat."""
        import socket
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind((self._host, self._port))
        self._transport, _ = await loop.create_datagram_endpoint(
            _SyslogProtocol,
            sock=sock,
        )
        logger.info(f"Syslog alıcısı başlatıldı: UDP {self._host}:{self._port}")

    def stop(self) -> None:
        """UDP dinlemeyi durdur."""
        if self._transport:
            self._transport.close()
            logger.info("Syslog alıcısı durduruldu.")
