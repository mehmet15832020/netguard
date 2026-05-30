"""
NetGuard Server — WebSocket endpoint

GET /ws  → Gerçek zamanlı metrik ve alert akışı
Auth: bağlantı sonrası {"type":"auth","token":"<jwt>"} mesajı (5s içinde)
Token URL'de gönderilmez — nginx log sızıntısını önler (RFC 6750 §5.3)
"""

import asyncio
import json
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from server.auth import verify_token
from server.ws_manager import ws_manager

logger = logging.getLogger(__name__)
router = APIRouter()

_AUTH_TIMEOUT = 5.0


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()

    try:
        raw = await asyncio.wait_for(ws.receive_text(), timeout=_AUTH_TIMEOUT)
        msg = json.loads(raw)
        if msg.get("type") != "auth" or not msg.get("token"):
            await ws.close(code=4401, reason="Auth mesajı bekleniyor")
            return
        payload = verify_token(msg["token"])
        if not payload:
            await ws.close(code=4401, reason="Geçersiz token")
            return
    except asyncio.TimeoutError:
        await ws.close(code=4401, reason="Auth timeout")
        return
    except (json.JSONDecodeError, WebSocketDisconnect):
        return

    await ws_manager.register(ws)
    try:
        while True:
            data = await ws.receive_text()
            try:
                m = json.loads(data)
                if m.get("type") == "ping":
                    await ws.send_text('{"type":"pong"}')
            except json.JSONDecodeError:
                if data == "ping":
                    await ws.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(ws)
