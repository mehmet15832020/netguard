"""
NetGuard Server — WebSocket endpoint

GET /ws?token=<jwt>  → Gerçek zamanlı metrik ve alert akışı
"""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from server.auth import verify_token
from server.ws_manager import ws_manager

logger = logging.getLogger(__name__)
router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(
    ws: WebSocket,
    token: str = Query(default=""),
):
    # Token doğrula
    payload = verify_token(token) if token else None
    if not payload:
        await ws.close(code=4401, reason="Geçersiz token")
        return

    await ws_manager.connect(ws)
    try:
        while True:
            # İstemciden ping gelebilir, cevap ver
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(ws)
