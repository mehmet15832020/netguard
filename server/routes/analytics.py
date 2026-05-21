"""
NetGuard — Analytics API

GET /api/v1/analytics/top-talkers
  - Top kaynak IP'ler (en çok trafik üreten)
  - Top hedef IP'ler (en çok trafik alan)
  - Top hedef portlar (geçerli port aralığı: 1-65535)
"""

import logging
from collections import defaultdict
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


_ALERT_HOUR_EXPR = "to_char(date_trunc('hour', triggered_at), 'YYYY-MM-DD\"T\"HH24:00:00\"Z\"')"
_SEVERITY_LEVELS = ("critical", "high", "warning", "info")


class _AlertPoint(BaseModel):
    t: str
    v: int


class AlertVolumeResponse(BaseModel):
    hours: int
    series: dict[str, list[_AlertPoint]]


@router.get("/analytics/alert-volume", response_model=AlertVolumeResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def alert_volume(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    if tid is None:
        tenant_clause = ""
        params: list = [since, now]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since, now, tid]

    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
                {_ALERT_HOUR_EXPR} AS hour,
                severity,
                COUNT(*) AS cnt
            FROM alerts
            WHERE triggered_at >= %s
              AND triggered_at <= %s
              {tenant_clause}
              AND severity IN ('critical', 'high', 'warning', 'info')
            GROUP BY hour, severity
            ORDER BY hour
            """,
            params,
        ).fetchall()

    # Pre-generate complete hourly axis so gaps are zero-filled, not dropped
    since_trunc = since.replace(minute=0, second=0, microsecond=0)
    now_trunc = now.replace(minute=0, second=0, microsecond=0)
    n_buckets = int((now_trunc - since_trunc).total_seconds() // 3600) + 1
    all_hours = [
        (since_trunc + timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00Z")
        for i in range(n_buckets)
    ]

    bucket: dict[str, dict[str, int]] = {h: {s: 0 for s in _SEVERITY_LEVELS} for h in all_hours}
    for r in rows:
        h = r["hour"]
        if h in bucket:
            bucket[h][r["severity"]] = r["cnt"]

    series: dict[str, list[_AlertPoint]] = {
        sev: [_AlertPoint(t=h, v=bucket[h][sev]) for h in all_hours]
        for sev in _SEVERITY_LEVELS
    }

    return AlertVolumeResponse(hours=hours, series=series)


class _ProtoCount(BaseModel):
    protocol: str
    count: int
    pct: float


class ProtocolDistributionResponse(BaseModel):
    hours: int
    total: int
    protocols: list[_ProtoCount]


@router.get("/analytics/protocol-distribution", response_model=ProtocolDistributionResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def protocol_distribution(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    if tid is None:
        tenant_clause = ""
        params: list = [since, since]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since, since, tid]

    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
                LOWER(network_protocol) AS proto,
                COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              AND timestamp >= %s
              {tenant_clause}
              AND network_protocol IS NOT NULL
              AND LENGTH(TRIM(network_protocol)) > 0
            GROUP BY proto
            ORDER BY cnt DESC
            LIMIT 50
            """,
            params,
        ).fetchall()

    total = sum(r["cnt"] for r in rows)
    protocols = [
        _ProtoCount(
            protocol=r["proto"],
            count=r["cnt"],
            pct=round(r["cnt"] / total * 100, 1) if total > 0 else 0.0,
        )
        for r in rows
    ]

    return ProtocolDistributionResponse(hours=hours, total=total, protocols=protocols)


_TRAFFIC_HOUR_EXPR = "to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD\"T\"HH24:00:00\"Z\"')"

_RFC1918_LIKE = """(
    source_ip LIKE '10.%'
    OR source_ip LIKE '192.168.%'
    OR source_ip LIKE '172.16.%' OR source_ip LIKE '172.17.%'
    OR source_ip LIKE '172.18.%' OR source_ip LIKE '172.19.%'
    OR source_ip LIKE '172.20.%' OR source_ip LIKE '172.21.%'
    OR source_ip LIKE '172.22.%' OR source_ip LIKE '172.23.%'
    OR source_ip LIKE '172.24.%' OR source_ip LIKE '172.25.%'
    OR source_ip LIKE '172.26.%' OR source_ip LIKE '172.27.%'
    OR source_ip LIKE '172.28.%' OR source_ip LIKE '172.29.%'
    OR source_ip LIKE '172.30.%' OR source_ip LIKE '172.31.%'
    OR source_ip LIKE '127.%'
    OR source_ip LIKE '169.254.%'
    OR source_ip LIKE 'fc%'
    OR source_ip LIKE 'fe80:%'
    OR source_ip = '::1'
)"""


class _TrafficPoint(BaseModel):
    t: str
    v: int


class TrafficVolumeResponse(BaseModel):
    hours: int
    series: dict[str, list[_TrafficPoint]]


@router.get("/analytics/traffic-volume", response_model=TrafficVolumeResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def traffic_volume(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    if tid is None:
        tenant_clause = ""
        params: list = [since, since]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since, since, tid]

    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
                {_TRAFFIC_HOUR_EXPR} AS hour,
                CASE WHEN {_RFC1918_LIKE} THEN 'internal' ELSE 'external' END AS direction,
                COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              AND timestamp >= %s
              {tenant_clause}
              AND source_ip IS NOT NULL
            GROUP BY hour, direction
            ORDER BY hour
            """,
            params,
        ).fetchall()

    since_trunc = since.replace(minute=0, second=0, microsecond=0)
    now_trunc = now.replace(minute=0, second=0, microsecond=0)
    n_buckets = int((now_trunc - since_trunc).total_seconds() // 3600) + 1
    all_hours = [
        (since_trunc + timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00Z")
        for i in range(n_buckets)
    ]

    bucket: dict[str, dict[str, int]] = {
        h: {"internal": 0, "external": 0} for h in all_hours
    }
    for r in rows:
        h = r["hour"]
        if h in bucket and r["direction"] in ("internal", "external"):
            bucket[h][r["direction"]] += r["cnt"]

    series: dict[str, list[_TrafficPoint]] = {
        direction: [_TrafficPoint(t=h, v=bucket[h][direction]) for h in all_hours]
        for direction in ("internal", "external")
    }

    return TrafficVolumeResponse(hours=hours, series=series)
