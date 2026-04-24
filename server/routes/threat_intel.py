"""
NetGuard — Threat Intelligence endpoint'leri

GET /api/v1/threat-intel/{ip}         → IP sorgusu (cache + AbuseIPDB)
GET /api/v1/threat-intel/batch        → Çoklu IP sorgusu
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from server.auth import get_current_user, User
from server import threat_intel

router = APIRouter()


@router.get("/threat-intel/{ip}")
def get_threat_intel(ip: str, _: User = Depends(get_current_user)):
    """Tek bir IP için TI skoru döndür."""
    result = threat_intel.lookup(ip)
    if result is None:
        return {"ip": ip, "score": None, "cached": False,
                "message": "Private IP veya API key eksik"}
    return {**result, "cached": True}


@router.get("/threat-intel")
def get_threat_intel_batch(
    ips: list[str] = Query(...),
    _: User = Depends(get_current_user),
):
    """Virgülle ayrılmış IP listesi için TI sorgusu."""
    if len(ips) > 20:
        raise HTTPException(status_code=400, detail="En fazla 20 IP sorgulanabilir")
    results = {}
    for ip in ips:
        results[ip] = threat_intel.lookup(ip)
    return {"results": results}
