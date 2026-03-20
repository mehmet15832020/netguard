"""
NetGuard Server — Health endpoint

GET /api/v1/health → Server'ın ayakta olup olmadığını söyler.
Load balancer'lar, monitoring araçları bu endpoint'i sorgular.
"""

from datetime import datetime, timezone
from fastapi import APIRouter
from server.storage import storage

router = APIRouter()


@router.get("/health")
def health_check():
    """Server sağlık kontrolü."""
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "registered_agents": storage.agent_count,
    }