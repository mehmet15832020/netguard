"""
NetGuard — Topology API

GET  /api/v1/topology/graph    → Tüm node ve edge'leri döndür
POST /api/v1/topology/refresh  → Topolojiyi yeniden oluştur (admin)
"""

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException

from server.auth import User, get_current_user, require_admin
from server.database import db

logger = logging.getLogger(__name__)
router = APIRouter()

_refresh_lock = asyncio.Lock()


@router.get("/topology/graph")
def get_graph(_: User = Depends(get_current_user)):
    """
    Topoloji grafiğini döndürür.
    nodes: cihazlar, edges: aralarındaki bağlantılar.
    """
    graph = db.get_topology_graph()
    return {
        "node_count": len(graph["nodes"]),
        "edge_count": len(graph["edges"]),
        "nodes": graph["nodes"],
        "edges": graph["edges"],
    }


@router.post("/topology/refresh", status_code=202)
async def refresh_topology(_: User = Depends(require_admin)):
    """
    Topolojiyi yeniden oluşturur — SNMP ARP/LLDP walk + subnet çıkarımı.
    Arka planda çalışır, anında 202 döner.
    """
    if _refresh_lock.locked():
        raise HTTPException(status_code=409, detail="Topoloji yenileme zaten çalışıyor")

    async def _run():
        async with _refresh_lock:
            from server.topology.builder import build_topology
            try:
                summary = await build_topology()
                logger.info(f"Topoloji yenilendi: {summary}")
            except Exception as exc:
                logger.error(f"Topoloji yenileme hatası: {exc}")

    asyncio.create_task(_run())
    return {"status": "started", "message": "Topoloji yenileme arka planda başlatıldı"}
