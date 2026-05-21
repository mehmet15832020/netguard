"""
NetGuard — Analytics API

GET /api/v1/analytics/top-talkers
  - Top kaynak IP'ler (en çok trafik üreten)
  - Top hedef IP'ler (en çok trafik alan)
  - Top hedef portlar (geçerli port aralığı: 1-65535)
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel

from server.auth import User, get_current_user, tenant_scope
from server.database import db
from server.limiter import _auth_key, limiter

logger = logging.getLogger(__name__)
router = APIRouter()


class _IPCount(BaseModel):
    ip: str
    count: int


class _PortCount(BaseModel):
    port: int
    count: int


class TopTalkersResponse(BaseModel):
    hours: int
    top_sources: list[_IPCount]
    top_destinations: list[_IPCount]
    top_dst_ports: list[_PortCount]


@router.get("/analytics/top-talkers", response_model=TopTalkersResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def top_talkers(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # TimescaleDB chunk pruning: received_at (partition key) + timestamp filtresi
    # received_at ile chunk exclusion aktif olur; timestamp ile kayıt zamanı doğrulanır
    if tid is None:
        # Superadmin — tüm tenant'lar
        tenant_clause = ""
        base_params = [since, since]
    else:
        tenant_clause = "AND tenant_id = %s"
        base_params = [since, since, tid]

    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT source_ip, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              AND timestamp >= %s
              {tenant_clause}
              AND source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT %s
            """,
            [*base_params, limit],
        ).fetchall()
        top_sources = [_IPCount(ip=r["source_ip"], count=r["cnt"]) for r in rows]

        rows = conn.execute(
            f"""
            SELECT destination_ip, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              AND timestamp >= %s
              {tenant_clause}
              AND destination_ip IS NOT NULL
            GROUP BY destination_ip
            ORDER BY cnt DESC
            LIMIT %s
            """,
            [*base_params, limit],
        ).fetchall()
        top_destinations = [_IPCount(ip=r["destination_ip"], count=r["cnt"]) for r in rows]

        rows = conn.execute(
            f"""
            SELECT destination_port, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              AND timestamp >= %s
              {tenant_clause}
              AND destination_port BETWEEN 1 AND 65535
            GROUP BY destination_port
            ORDER BY cnt DESC
            LIMIT %s
            """,
            [*base_params, limit],
        ).fetchall()
        top_dst_ports = [_PortCount(port=r["destination_port"], count=r["cnt"]) for r in rows]

    return TopTalkersResponse(
        hours=hours,
        top_sources=top_sources,
        top_destinations=top_destinations,
        top_dst_ports=top_dst_ports,
    )
