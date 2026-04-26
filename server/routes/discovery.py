"""
NetGuard — Auto-Discovery API

POST /api/v1/discovery/scan    → Subnet tarama başlatır (arka plan)
GET  /api/v1/discovery/results → Keşfedilen cihazları döndürür
GET  /api/v1/discovery/status  → Aktif tarama durumu
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from server.auth import User, get_current_user, require_admin, tenant_scope
from server.database import db

logger = logging.getLogger(__name__)
router = APIRouter()

# Aktif tarama durumu (in-memory — tek process varsayımı)
_scan_state: dict = {
    "running": False,
    "scan_id": None,
    "cidr": None,
    "started_at": None,
    "found": 0,
    "total_probed": 0,
    "finished_at": None,
    "error": "",
}


class ScanRequest(BaseModel):
    cidr: str
    community: str = "public"
    fingerprint: bool = True


@router.post("/discovery/scan", status_code=202)
async def start_scan(
    req: ScanRequest,
    current_user: User = Depends(require_admin),
):
    """Subnet tarama başlatır — arka planda çalışır."""
    if _scan_state["running"]:
        raise HTTPException(status_code=409, detail="Zaten bir tarama çalışıyor")

    scan_id = str(uuid.uuid4())[:8]
    tenant_id = current_user.tenant_id or "default"
    _scan_state.update({
        "running": True,
        "scan_id": scan_id,
        "cidr": req.cidr,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "found": 0,
        "total_probed": 0,
        "finished_at": None,
        "error": "",
    })

    asyncio.create_task(_run_scan(req.cidr, req.community, req.fingerprint, scan_id, tenant_id))
    return {"scan_id": scan_id, "cidr": req.cidr, "status": "started"}


@router.get("/discovery/status")
def scan_status(_: User = Depends(get_current_user)):
    """Aktif/son taramanın durumunu döndürür."""
    return _scan_state.copy()


@router.get("/discovery/results")
def discovery_results(
    limit: int = 100,
    current_user: User = Depends(get_current_user),
):
    """Keşfedilen cihazları döndürür."""
    devices = db.get_devices(device_type="discovered", tenant_id=tenant_scope(current_user))
    return {"count": len(devices), "devices": devices[:limit]}


async def _run_scan(cidr: str, community: str, do_fingerprint: bool, scan_id: str, tenant_id: str = "default"):
    """Arka plan tarama görevi."""
    from server.discovery.subnet_scanner import sweep
    from server.discovery.fingerprinter import fingerprint

    try:
        active_hosts = await sweep(cidr)
        _scan_state["total_probed"] = _count_hosts(cidr)

        for host_info in active_hosts:
            ip = host_info["ip"]
            fp: dict = {"ip": ip, "open_ports": [], "vendor": "", "sys_name": "", "os_hint": ""}

            if do_fingerprint:
                try:
                    fp = await fingerprint(ip)
                except Exception as exc:
                    logger.warning(f"Fingerprint hatası ({ip}): {exc}")

            name = fp.get("sys_name") or ip
            db.save_device(
                device_id=ip,
                name=name,
                device_type="discovered",
                ip=ip,
                os_info=fp.get("os_hint", ""),
                status="up",
                notes=_build_notes(fp),
                tenant_id=tenant_id,
            )
            _scan_state["found"] += 1
            logger.info(f"Keşfedildi: {ip} ({name})")

    except Exception as exc:
        logger.error(f"Subnet tarama hatası: {exc}")
        _scan_state["error"] = str(exc)
    finally:
        _scan_state["running"] = False
        _scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
        logger.info(
            f"Tarama tamamlandı [{scan_id}]: {_scan_state['found']} cihaz bulundu"
        )


def _count_hosts(cidr: str) -> int:
    from ipaddress import ip_network
    try:
        return sum(1 for _ in ip_network(cidr, strict=False).hosts())
    except ValueError:
        return 0


def _build_notes(fp: dict) -> str:
    parts = []
    if fp.get("vendor"):
        parts.append(f"vendor:{fp['vendor']}")
    if fp.get("open_ports"):
        ports = ",".join(str(p) for p in sorted(fp["open_ports"]))
        parts.append(f"ports:{ports}")
    if fp.get("sys_descr"):
        parts.append(f"descr:{fp['sys_descr'][:80]}")
    return " | ".join(parts)
