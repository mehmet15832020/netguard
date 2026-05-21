"""
NetGuard — Analytics API

GET /api/v1/analytics/top-talkers
  - Top kaynak IP'ler (en çok trafik üreten)
  - Top hedef IP'ler (en çok trafik alan)
  - Top hedef portlar
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query

from server.auth import User, get_current_user, tenant_scope
from server.database import db

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/analytics/top-talkers")
def top_talkers(
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    tenant_id = tenant_scope(current_user)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    with db._connect() as conn:
        rows = conn.execute(
            """
            SELECT source_ip, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE timestamp >= %s
              AND tenant_id = %s
              AND source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT %s
            """,
            [since, tenant_id, limit],
        ).fetchall()
        top_sources = [{"ip": r["source_ip"], "count": r["cnt"]} for r in rows]

        rows = conn.execute(
            """
            SELECT destination_ip, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE timestamp >= %s
              AND tenant_id = %s
              AND destination_ip IS NOT NULL
            GROUP BY destination_ip
            ORDER BY cnt DESC
            LIMIT %s
            """,
            [since, tenant_id, limit],
        ).fetchall()
        top_destinations = [{"ip": r["destination_ip"], "count": r["cnt"]} for r in rows]

        rows = conn.execute(
            """
            SELECT destination_port, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE timestamp >= %s
              AND tenant_id = %s
              AND destination_port IS NOT NULL
            GROUP BY destination_port
            ORDER BY cnt DESC
            LIMIT %s
            """,
            [since, tenant_id, limit],
        ).fetchall()
        top_dst_ports = [{"port": r["destination_port"], "count": r["cnt"]} for r in rows]

    return {
        "hours": hours,
        "top_sources": top_sources,
        "top_destinations": top_destinations,
        "top_dst_ports": top_dst_ports,
    }
