"""
NetGuard — Rapor endpoint'leri

GET /api/v1/reports/summary           → JSON özet (dashboard için)
GET /api/v1/reports/devices.csv       → Cihaz envanteri CSV
GET /api/v1/reports/alerts.csv        → Alert geçmişi CSV
GET /api/v1/reports/security.csv      → Güvenlik olayları CSV
GET /api/v1/reports/topology.csv      → Topoloji kenarları CSV
"""

import csv
import io
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from server.auth import get_current_user, User, tenant_scope
import server.database as _db_mod

router = APIRouter()


def _csv_response(rows: list[dict], filename: str) -> StreamingResponse:
    """Dict listesini CSV StreamingResponse'a çevirir."""
    if not rows:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["no_data"])
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/reports/summary")
def report_summary(current_user: User = Depends(get_current_user)):
    """Kullanıcının tenant'ına ait özet — dashboard widget ve rapor sayfası için."""
    tid         = tenant_scope(current_user)
    devices     = _db_mod.db.get_devices(tenant_id=tid)
    alerts      = _db_mod.db.get_alerts(status="active", limit=1000, tenant_id=tid)
    sec_events  = _db_mod.db.get_security_events(limit=1000, tenant_id=tid)
    topology    = _db_mod.db.get_topology_graph()

    device_by_type: dict[str, int] = {}
    for d in devices:
        t = d.get("type", "") if isinstance(d, dict) else str(getattr(d, "type", ""))
        device_by_type[t] = device_by_type.get(t, 0) + 1

    device_by_status: dict[str, int] = {}
    for d in devices:
        s = d.get("status", "") if isinstance(d, dict) else str(getattr(d, "status", ""))
        device_by_status[s] = device_by_status.get(s, 0) + 1

    alert_by_severity: dict[str, int] = {}
    for a in alerts:
        sev = a.get("severity", "") if isinstance(a, dict) else str(getattr(a, "severity", ""))
        alert_by_severity[sev] = alert_by_severity.get(sev, 0) + 1

    sec_by_type: dict[str, int] = {}
    for e in sec_events:
        _et = getattr(e, "event_type", e.get("event_type", "") if isinstance(e, dict) else "")
        et = _et.value if hasattr(_et, "value") else str(_et)
        sec_by_type[et] = sec_by_type.get(et, 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "devices": {
            "total":      len(devices),
            "by_type":    device_by_type,
            "by_status":  device_by_status,
        },
        "alerts": {
            "active":      len(alerts),
            "by_severity": alert_by_severity,
        },
        "security": {
            "total":   len(sec_events),
            "by_type": sec_by_type,
        },
        "topology": {
            "nodes": len(topology["nodes"]),
            "edges": len(topology["edges"]),
        },
    }


@router.get("/reports/devices.csv")
def report_devices(
    device_type: str = Query(default=""),
    current_user: User = Depends(get_current_user),
):
    """Cihaz envanterini CSV olarak indir."""
    all_devices = _db_mod.db.get_devices(device_type=device_type or None, tenant_id=tenant_scope(current_user))
    safe_fields = [
        "device_id", "name", "ip", "mac", "type", "vendor",
        "os_info", "status", "snmp_version", "segment",
        "first_seen", "last_seen", "notes",
    ]
    rows = [{f: d.get(f, "") for f in safe_fields} for d in all_devices]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return _csv_response(rows, f"netguard_devices_{ts}.csv")


@router.get("/reports/alerts.csv")
def report_alerts(
    limit: int = Query(default=1000, le=5000),
    current_user: User = Depends(get_current_user),
):
    """Alert geçmişini CSV olarak indir."""
    raw = _db_mod.db.get_alerts(limit=limit, tenant_id=tenant_scope(current_user))
    rows = [{
        "alert_id":    a.alert_id if not isinstance(a, dict) else a.get("alert_id", ""),
        "severity":    str(a.severity) if not isinstance(a, dict) else a.get("severity", ""),
        "message":     (a.message if not isinstance(a, dict) else a.get("message", "")) or "",
        "hostname":    (a.hostname if not isinstance(a, dict) else a.get("hostname", "")) or "",
        "status":      str(a.status) if not isinstance(a, dict) else a.get("status", ""),
        "created_at":  a.triggered_at.isoformat() if not isinstance(a, dict) else a.get("created_at", ""),
        "resolved_at": a.resolved_at.isoformat() if (not isinstance(a, dict) and a.resolved_at) else (a.get("resolved_at", "") if isinstance(a, dict) else ""),
    } for a in raw]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return _csv_response(rows, f"netguard_alerts_{ts}.csv")


@router.get("/reports/security.csv")
def report_security(
    limit: int = Query(default=2000, le=10000),
    current_user: User = Depends(get_current_user),
):
    """Güvenlik olaylarını CSV olarak indir."""
    raw = _db_mod.db.get_security_events(limit=limit, tenant_id=tenant_scope(current_user))
    rows = [{
        "event_id":   e.event_id if not isinstance(e, dict) else e.get("event_id", ""),
        "event_type": e.event_type.value if (not isinstance(e, dict) and hasattr(e.event_type, "value")) else (e.get("event_type", "") if isinstance(e, dict) else str(e.event_type)),
        "source_ip":  (e.source_ip if not isinstance(e, dict) else e.get("source_ip", "")) or "",
        "username":   (e.username if not isinstance(e, dict) else e.get("username", "")) or "",
        "message":    (e.message if not isinstance(e, dict) else e.get("message", "")) or "",
        "agent_id":   (e.agent_id if not isinstance(e, dict) else e.get("agent_id", "")) or "",
        "severity":   (e.severity if not isinstance(e, dict) else e.get("severity", "")) or "",
        "raw_log":    (e.raw_data if not isinstance(e, dict) else e.get("raw_data", "")) or "",
        "detected_at": e.occurred_at.isoformat() if not isinstance(e, dict) else e.get("occurred_at", ""),
    } for e in raw]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return _csv_response(rows, f"netguard_security_{ts}.csv")


@router.get("/reports/topology.csv")
def report_topology(current_user: User = Depends(get_current_user)):  # noqa: ARG001 — topology henüz tenant-aware değil
    """Topoloji kenarlarını CSV olarak indir."""
    graph   = _db_mod.db.get_topology_graph()
    nodes_by_id = {n["node_id"]: n for n in graph["nodes"]}

    rows = []
    for edge in graph["edges"]:
        src = nodes_by_id.get(edge["source_id"], {})
        dst = nodes_by_id.get(edge["target_id"], {})
        rows.append({
            "source_id":   edge["source_id"],
            "source_name": src.get("name", ""),
            "source_ip":   src.get("ip", ""),
            "target_id":   edge["target_id"],
            "target_name": dst.get("name", ""),
            "target_ip":   dst.get("ip", ""),
            "link_type":   edge.get("link_type", ""),
            "discovered":  edge.get("discovered", ""),
        })
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return _csv_response(rows, f"netguard_topology_{ts}.csv")
