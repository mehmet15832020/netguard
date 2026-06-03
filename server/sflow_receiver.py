"""
NetGuard — sFlow v5 UDP Receiver

sFlow v5 datagramlarını UDP 6343'ten alır, parse eder,
normalized_logs tablosuna yazar.

RFC 3176 / sFlow.org v5 specification.
"""

import asyncio
import logging
import os

from server.log_store import log_store
from server.parsers.netflow import parse_sflow

logger = logging.getLogger(__name__)

SFLOW_HOST = os.getenv("SFLOW_HOST", "0.0.0.0")
SFLOW_PORT = int(os.getenv("SFLOW_PORT", "6343"))


class SFlowProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self._transport = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport
        logger.info("sFlow receiver UDP %s:%d hazır", SFLOW_HOST, SFLOW_PORT)

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        observer = addr[0]
        try:
            flows = parse_sflow(data, observer)
        except Exception as exc:
            logger.debug("sFlow parse hatası [%s]: %s", observer, exc)
            return
        for flow in flows:
            try:
                log_store.save(flow)
            except Exception as exc:
                logger.error("sFlow kayıt hatası: %s", exc)

    def error_received(self, exc: Exception) -> None:
        logger.warning("sFlow UDP hata: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        logger.info("sFlow receiver kapatıldı")


async def run_sflow_receiver() -> None:
    """asyncio task — sFlow UDP dinleme döngüsü."""
    loop = asyncio.get_event_loop()
    try:
        await loop.create_datagram_endpoint(
            SFlowProtocol,
            local_addr=(SFLOW_HOST, SFLOW_PORT),
        )
        logger.info("sFlow receiver başlatıldı (UDP %s:%d)", SFLOW_HOST, SFLOW_PORT)
        await asyncio.Future()
    except OSError as exc:
        logger.error("sFlow receiver başlatılamadı: %s", exc)
