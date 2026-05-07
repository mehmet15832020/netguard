"""
NetGuard Server — WebSocket bağlantı yöneticisi

Tüm aktif WebSocket bağlantılarını tutar ve mesaj broadcast eder.
"""

import asyncio
import json
import logging
from typing import Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(self):
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        logger.info(f"WS bağlandı — aktif: {len(self._connections)}")

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        logger.info(f"WS ayrıldı — aktif: {len(self._connections)}")

    async def broadcast(self, msg_type: str, data: Any) -> None:
        """Tüm bağlı istemcilere mesaj gönder. Kopuk bağlantıları temizle."""
        if not self._connections:
            return

        payload = json.dumps({"type": msg_type, "data": data}, default=str)

        dead: set[WebSocket] = set()
        async with self._lock:
            targets = set(self._connections)

        for ws in targets:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)

        if dead:
            async with self._lock:
                self._connections -= dead

    def broadcast_from_thread(self, msg_type: str, data: Any) -> None:
        """Thread context'inden (asyncio.to_thread içinden) broadcast zamanla."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(self.broadcast(msg_type, data), loop)
        except Exception:
            pass

    @property
    def connection_count(self) -> int:
        return len(self._connections)


ws_manager = WebSocketManager()
