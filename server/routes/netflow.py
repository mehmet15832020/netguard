"""
NetGuard Server — NetFlow endpoint'leri

GET  /api/v1/netflow/status   → Receiver durumu (port, paket sayısı, akış sayısı)
"""

from fastapi import APIRouter, Depends

from server.auth import User, get_current_user
from server.netflow_receiver import NetFlowReceiver

router = APIRouter()


@router.get("/netflow/status")
def netflow_status(_: User = Depends(get_current_user)):
    """NetFlow receiver'ın güncel durumunu döner."""
    return NetFlowReceiver.stats()
