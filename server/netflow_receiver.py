"""
NetGuard — NetFlow UDP Receiver

UDP port 2055'i asyncio ile dinler.
Gelen her paketi NetFlow v5/v9 parser'a iletir, parse edilen akışları DB'ye kaydeder.
"""

import asyncio
import logging
import os

from server.parsers.netflow import detect_and_parse

logger = logging.getLogger(__name__)

NETFLOW_HOST = os.getenv("NETGUARD_NETFLOW_HOST", "0.0.0.0")
NETFLOW_PORT = int(os.getenv("NETGUARD_NETFLOW_PORT", "2055"))

_packets_received = 0
_flows_stored     = 0


class _NetFlowProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr: tuple) -> None:
        global _packets_received, _flows_stored
        source_host = addr[0]
        _packets_received += 1
        try:
            from server.database import db
            logs = detect_and_parse(data, source_host)
            for log in logs:
                db.save_normalized_log(log)
            _flows_stored += len(logs)
            if logs:
                logger.debug(
                    f"NetFlow {addr[0]}: {len(logs)} akış kaydedildi "
                    f"(toplam paket={_packets_received})"
                )
        except Exception as exc:
            logger.error(f"NetFlow işleme hatası ({source_host}): {exc}")

    def error_received(self, exc: Exception) -> None:
        logger.warning(f"NetFlow UDP hatası: {exc}")


class NetFlowReceiver:
    def __init__(self) -> None:
        self._transport = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                _NetFlowProtocol,
                local_addr=(NETFLOW_HOST, NETFLOW_PORT),
            )
            logger.info(f"NetFlow receiver başlatıldı: UDP {NETFLOW_HOST}:{NETFLOW_PORT}")
        except OSError as exc:
            logger.warning(f"NetFlow receiver başlatılamadı (port {NETFLOW_PORT}): {exc}")

    def stop(self) -> None:
        if self._transport:
            self._transport.close()
            logger.info("NetFlow receiver durduruldu.")

    @staticmethod
    def stats() -> dict:
        return {
            "packets_received": _packets_received,
            "flows_stored":     _flows_stored,
            "host":             NETFLOW_HOST,
            "port":             NETFLOW_PORT,
        }
