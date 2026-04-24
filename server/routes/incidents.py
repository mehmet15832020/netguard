"""
NetGuard Server — Incident yönetimi endpoint'leri

POST   /api/v1/incidents                → Yeni incident oluştur
GET    /api/v1/incidents                → Listele (status/severity/assigned_to filtresi)
GET    /api/v1/incidents/{id}           → Tekil incident
PATCH  /api/v1/incidents/{id}           → Durum/atama/notlar güncelle
DELETE /api/v1/incidents/{id}           → Sil (admin)
GET    /api/v1/incidents/summary        → Özet sayılar
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from server.auth import User, get_current_user
from server.database import db
from shared.models import Incident, IncidentStatus

router = APIRouter()


class CreateIncidentRequest(BaseModel):
    title: str
    description: str = ""
    severity: str = "warning"
    assigned_to: Optional[str] = None
    source_event_id: Optional[str] = None
    source_type: Optional[str] = None
    notes: str = ""


class UpdateIncidentRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None


@router.post("/incidents", status_code=201)
def create_incident(
    req: CreateIncidentRequest,
    current_user: User = Depends(get_current_user),
):
    if req.severity not in ("info", "warning", "critical"):
        raise HTTPException(status_code=400, detail="severity: info | warning | critical")

    incident = Incident(
        incident_id     = str(uuid.uuid4()),
        title           = req.title,
        description     = req.description,
        severity        = req.severity,
        status          = IncidentStatus.OPEN,
        assigned_to     = req.assigned_to,
        source_event_id = req.source_event_id,
        source_type     = req.source_type,
        created_by      = current_user.username,
        notes           = req.notes,
    )
    db.create_incident(incident)
    db.save_audit_event(
        actor=current_user.username,
        action="incident_created",
        resource=f"incident:{incident.incident_id}",
        detail=req.title,
    )
    return incident


@router.get("/incidents/summary")
def incidents_summary(_: User = Depends(get_current_user)):
    """Her durum için incident sayısını döner."""
    return {
        "open":          db.count_incidents(status="open"),
        "investigating": db.count_incidents(status="investigating"),
        "resolved":      db.count_incidents(status="resolved"),
        "total":         db.count_incidents(),
    }


@router.get("/incidents")
def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = 100,
    _: User = Depends(get_current_user),
):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit 1-500 arasında olmalı")
    rows = db.get_incidents(
        status=status, severity=severity, assigned_to=assigned_to, limit=limit
    )
    return {"count": len(rows), "incidents": rows}


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, _: User = Depends(get_current_user)):
    row = db.get_incident(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident bulunamadı")
    return row


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: str,
    req: UpdateIncidentRequest,
    current_user: User = Depends(get_current_user),
):
    valid_statuses = {s.value for s in IncidentStatus}
    if req.status and req.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Geçerli status: {valid_statuses}")

    updated = db.update_incident(
        incident_id,
        status=req.status,
        assigned_to=req.assigned_to,
        notes=req.notes,
        title=req.title,
        description=req.description,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Incident bulunamadı")

    db.save_audit_event(
        actor=current_user.username,
        action="incident_updated",
        resource=f"incident:{incident_id}",
        detail=str(req.model_dump(exclude_none=True)),
    )
    return db.get_incident(incident_id)


@router.get("/incidents/{incident_id}/events")
def get_incident_events(incident_id: str, _: User = Depends(get_current_user)):
    if not db.get_incident(incident_id):
        raise HTTPException(status_code=404, detail="Incident bulunamadı")
    events = db.get_incident_events(incident_id)
    return {"incident_id": incident_id, "count": len(events), "events": events}


@router.delete("/incidents/{incident_id}", status_code=204)
def delete_incident(
    incident_id: str,
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Sadece admin silebilir")
    if not db.delete_incident(incident_id):
        raise HTTPException(status_code=404, detail="Incident bulunamadı")
    db.save_audit_event(
        actor=current_user.username,
        action="incident_deleted",
        resource=f"incident:{incident_id}",
    )
