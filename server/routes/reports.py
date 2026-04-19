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
from server.auth import get_current_user, User
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
def report_summary(_: User = Depends(get_current_user)):
    """Sistem geneli özet — dashboard widget ve rapor sayfası için."""
    devices     = _db_mod.db.get_devices()
    alerts      = _db_mod.db.get_alerts(status="active", limit=1000)
    sec_events  = _db_mod.db.get_security_events(limit=1000)
    topology    = _db_mod.db.get_topology_graph()

    device_by_type: dict[str, int] = {}
    for d in devices:
        device_by_type[d["type"]] = device_by_type.get(d["type"], 0) + 1

    device_by_status: dict[str, int] = {}
    for d in devices:
        device_by_status[d["status"]] = device_by_status.get(d["status"], 0) + 1

    alert_by_severity: dict[str, int] = {}
    for a in alerts:
        alert_by_severity[a["severity"]] = alert_by_severity.get(a["severity"], 0) + 1

    sec_by_type: dict[str, int] = {}
    for e in sec_events:
        sec_by_type[e["event_type"]] = sec_by_type.get(e["event_type"], 0) + 1

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
    _: User = Depends(get_current_user),
):
    """Cihaz envanterini CSV olarak indir."""
    all_devices = _db_mod.db.get_devices(device_type=device_type or None)
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
    _: User = Depends(get_current_user),
):
    """Alert geçmişini CSV olarak indir."""
    raw = _db_mod.db.get_alerts(limit=limit)
    fields = ["alert_id", "severity", "message", "hostname", "status", "created_at", "resolved_at"]
    rows = [{f: a.get(f, "") for f in fields} for a in raw]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return _csv_response(rows, f"netguard_alerts_{ts}.csv")


@router.get("/reports/security.csv")
def report_security(
    limit: int = Query(default=2000, le=10000),
    _: User = Depends(get_current_user),
):
    """Güvenlik olaylarını CSV olarak indir."""
    raw = _db_mod.db.get_security_events(limit=limit)
    fields = ["event_id", "event_type", "source_ip", "username", "message",
              "agent_id", "severity", "raw_log", "detected_at"]
    rows = [{f: e.get(f, "") for f in fields} for e in raw]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return _csv_response(rows, f"netguard_security_{ts}.csv")


@router.get("/reports/topology.csv")
def report_topology(_: User = Depends(get_current_user)):
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
