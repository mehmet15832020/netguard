"""
NetGuard — Asset Baseline API

GET /assets/baselines          — tüm asset profilleri
GET /assets/baselines/{ip}     — tek IP'nin profili
POST /assets/baselines/refresh — baseline'ı hemen yenile (manuel tetikleme)
"""

from fastapi import APIRouter, HTTPException, Depends
from server.database import db
from server.auth import get_current_user

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("/baselines")
def list_baselines(
    tenant_id: str = "default",
    _user=Depends(get_current_user),
):
    baselines = db.get_all_asset_baselines(tenant_id=tenant_id)
    return sorted(baselines.values(), key=lambda x: x["avg_events_per_hour"], reverse=True)


@router.get("/baselines/{source_ip:path}")
def get_baseline(
    source_ip: str,
    tenant_id: str = "default",
    _user=Depends(get_current_user),
):
    bl = db.get_asset_baseline(source_ip=source_ip, tenant_id=tenant_id)
    if not bl:
        raise HTTPException(status_code=404, detail=f"{source_ip} için baseline bulunamadı")
    return bl


@router.post("/baselines/refresh")
def refresh_baselines(
    tenant_id: str = "default",
    _user=Depends(get_current_user),
):
    from server.asset_baseline import update_baselines
    count = update_baselines(tenant_id=tenant_id)
    return {"updated": count, "tenant_id": tenant_id}
