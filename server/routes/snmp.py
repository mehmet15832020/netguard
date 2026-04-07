"""
NetGuard Server — SNMP endpoint'leri
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from server.auth import get_current_user, User

router = APIRouter()


class SNMPPollRequest(BaseModel):
    host: str
    community: str = "public"


@router.post("/snmp/poll")
def snmp_poll(
    request: SNMPPollRequest,
    _: User = Depends(get_current_user),
):
    """Belirtilen cihazı SNMP ile sorgula."""
    try:
        from agent.snmp_collector import poll_device
        result = poll_device(request.host, request.community)
        return result
    except ImportError:
        return {
            "host": request.host,
            "reachable": False,
            "error": "pysnmp kurulu değil"
        }