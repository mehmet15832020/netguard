"""
NetGuard Server — SNMP endpoint'leri

POST /api/v1/snmp/poll → Bir cihazı SNMP ile sorgula
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from agent.snmp_collector import poll_device
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
    result = poll_device(request.host, request.community)
    return result