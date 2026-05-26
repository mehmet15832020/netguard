"""
NetGuard — Analytics API

GET /api/v1/analytics/top-talkers           Top kaynak/hedef IP ve port sıralaması
GET /api/v1/analytics/alert-volume          Saatlik alert hacmi × severity (stacked area)
GET /api/v1/analytics/protocol-distribution Network protokol dağılımı (donut)
GET /api/v1/analytics/traffic-volume        East-West / North-South trafik hacmi (stacked area)
GET /api/v1/analytics/failed-auth           Başarısız kimlik doğrulama analizi
GET /api/v1/analytics/dns-analysis          DNS sorgu analizi
GET /api/v1/analytics/tls-fingerprints      TLS bağlantı parmak izi analizi
GET /api/v1/analytics/beaconing-summary     C2 beaconing tespiti özeti
GET /api/v1/analytics/threat-summary        Kritik tehdit özeti
GET /api/v1/analytics/kill-chain-timeline   Kill chain swimlane — IP başına aşama olayları zaman çizelgesi
GET /api/v1/analytics/source-health         Veri kaynağı sağlık durumu (son log zamanı × source_type)
"""

import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel

from server.auth import User, get_current_user, tenant_scope
from server.database import db
from server.limiter import _auth_key, limiter

logger = logging.getLogger(__name__)
router = APIRouter()


def _to_dt(s) -> datetime:
    if isinstance(s, datetime):
        return s
    return datetime.fromisoformat(str(s).replace("Z", "+00:00"))


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

    if tid is None:
        tenant_clause = ""
        base_params = [since]
    else:
        tenant_clause = "AND tenant_id = %s"
        base_params = [since, tid]

    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT source_ip, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
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


# ─── Alert Volume ─────────────────────────────────────────────────────────────

_SEVERITY_LEVELS = ("critical", "high", "warning", "info")


def _bucket_minutes(hours: int) -> int:
    if hours <= 24:
        return 60
    return 240


_ALERT_HOUR_EXPR = "to_char(date_trunc('hour', triggered_at), 'YYYY-MM-DD\"T\"HH24:00:00\"Z\"')"


class _AlertPoint(BaseModel):
    t: str
    v: int


class AlertVolumeResponse(BaseModel):
    hours: int
    bucket_minutes: int
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
    bm = _bucket_minutes(hours)

    # SQL always groups by hour (portable across SQLite + PG).
    # Zero-fill step uses bm to produce the correct number of buckets.
    since_hour = since.replace(minute=0, second=0, microsecond=0)
    now_hour = now.replace(minute=0, second=0, microsecond=0)

    _sev_ph = ", ".join(["%s"] * len(_SEVERITY_LEVELS))
    if tid is None:
        tenant_clause = ""
        params: list = [since_hour, now, *_SEVERITY_LEVELS]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since_hour, now, tid, *_SEVERITY_LEVELS]

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
              AND severity IN ({_sev_ph})
            GROUP BY hour, severity
            ORDER BY hour
            """,
            params,
        ).fetchall()

    # Build zero-filled hourly axis; aggregate into bm-sized buckets in Python
    n_hours = int((now_hour - since_hour).total_seconds() // 3600) + 1
    all_hours = [
        (since_hour + timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00Z")
        for i in range(n_hours)
    ]

    # Accumulate DB rows into hourly dict
    hour_sev: dict[str, dict[str, int]] = {h: {s: 0 for s in _SEVERITY_LEVELS} for h in all_hours}
    for r in rows:
        h = r["hour"]
        if h in hour_sev:
            hour_sev[h][r["severity"]] = r["cnt"]

    # Merge hours into bm-minute buckets if needed
    if bm == 60:
        all_buckets = all_hours
        bucket: dict[str, dict[str, int]] = hour_sev
    else:
        step_hours = bm // 60
        merged: dict[str, dict[str, int]] = {}
        for i, h in enumerate(all_hours):
            group_idx = i // step_hours
            group_key = all_hours[group_idx * step_hours]
            if group_key not in merged:
                merged[group_key] = {s: 0 for s in _SEVERITY_LEVELS}
            for sev in _SEVERITY_LEVELS:
                merged[group_key][sev] += hour_sev[h][sev]
        all_buckets = list(merged.keys())
        bucket = merged

    series: dict[str, list[_AlertPoint]] = {
        sev: [_AlertPoint(t=b, v=bucket[b][sev]) for b in all_buckets]
        for sev in _SEVERITY_LEVELS
    }

    return AlertVolumeResponse(hours=hours, bucket_minutes=bm, series=series)


# ─── Protocol Distribution ────────────────────────────────────────────────────

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
        params: list = [since]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since, tid]

    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
                LOWER(network_protocol) AS proto,
                COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
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


# ─── Traffic Volume — East-West 3-way ────────────────────────────────────────

_TRAFFIC_HOUR_EXPR = "to_char(date_trunc('hour', received_at), 'YYYY-MM-DD\"T\"HH24:00:00\"Z\"')"

_RFC1918_LIKE = """(
    source_ip LIKE '10.%%'
    OR source_ip LIKE '192.168.%%'
    OR source_ip LIKE '172.16.%%' OR source_ip LIKE '172.17.%%'
    OR source_ip LIKE '172.18.%%' OR source_ip LIKE '172.19.%%'
    OR source_ip LIKE '172.20.%%' OR source_ip LIKE '172.21.%%'
    OR source_ip LIKE '172.22.%%' OR source_ip LIKE '172.23.%%'
    OR source_ip LIKE '172.24.%%' OR source_ip LIKE '172.25.%%'
    OR source_ip LIKE '172.26.%%' OR source_ip LIKE '172.27.%%'
    OR source_ip LIKE '172.28.%%' OR source_ip LIKE '172.29.%%'
    OR source_ip LIKE '172.30.%%' OR source_ip LIKE '172.31.%%'
    OR source_ip LIKE '100.64.%%'
    OR source_ip LIKE '127.%%'
    OR source_ip LIKE '169.254.%%'
    OR source_ip LIKE 'fc%%' OR source_ip LIKE 'fd%%'
    OR source_ip LIKE 'fe80:%%'
    OR source_ip = '::1'
)"""

_RFC1918_DST_LIKE = """(
    destination_ip LIKE '10.%%'
    OR destination_ip LIKE '192.168.%%'
    OR destination_ip LIKE '172.16.%%' OR destination_ip LIKE '172.17.%%'
    OR destination_ip LIKE '172.18.%%' OR destination_ip LIKE '172.19.%%'
    OR destination_ip LIKE '172.20.%%' OR destination_ip LIKE '172.21.%%'
    OR destination_ip LIKE '172.22.%%' OR destination_ip LIKE '172.23.%%'
    OR destination_ip LIKE '172.24.%%' OR destination_ip LIKE '172.25.%%'
    OR destination_ip LIKE '172.26.%%' OR destination_ip LIKE '172.27.%%'
    OR destination_ip LIKE '172.28.%%' OR destination_ip LIKE '172.29.%%'
    OR destination_ip LIKE '172.30.%%' OR destination_ip LIKE '172.31.%%'
    OR destination_ip LIKE '100.64.%%'
    OR destination_ip LIKE '127.%%'
    OR destination_ip LIKE '169.254.%%'
    OR destination_ip LIKE 'fc%%' OR destination_ip LIKE 'fd%%'
    OR destination_ip LIKE 'fe80:%%'
    OR destination_ip = '::1'
)"""

_TRAFFIC_DIRECTIONS = ("east_west", "ns_egress", "ns_ingress")


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
    since_trunc = since.replace(minute=0, second=0, microsecond=0)

    if tid is None:
        tenant_clause = ""
        params: list = [since_trunc]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since_trunc, tid]

    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
                {_TRAFFIC_HOUR_EXPR} AS hour,
                CASE
                    WHEN {_RFC1918_LIKE} AND {_RFC1918_DST_LIKE} THEN 'east_west'
                    WHEN {_RFC1918_LIKE} THEN 'ns_egress'
                    WHEN {_RFC1918_DST_LIKE} THEN 'ns_ingress'
                    ELSE NULL
                END AS direction,
                COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND source_ip IS NOT NULL
              AND destination_ip IS NOT NULL
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
        h: {d: 0 for d in _TRAFFIC_DIRECTIONS} for h in all_hours
    }
    for r in rows:
        h = r["hour"]
        direction = r["direction"]
        if h in bucket and direction in _TRAFFIC_DIRECTIONS:
            bucket[h][direction] += r["cnt"]

    series: dict[str, list[_TrafficPoint]] = {
        direction: [_TrafficPoint(t=h, v=bucket[h][direction]) for h in all_hours]
        for direction in _TRAFFIC_DIRECTIONS
    }

    return TrafficVolumeResponse(hours=hours, series=series)


# ─── Failed Auth ─────────────────────────────────────────────────────────────

_FAILED_AUTH_ACTIONS = (
    "ssh_failure",
    "brute_force_detected",
    "windows_logon_failure",
    "failed_login",
    "authentication_failed",
)

_NORM_HOUR_EXPR = "to_char(date_trunc('hour', received_at), 'YYYY-MM-DD\"T\"HH24:00:00\"Z\"')"


class _TargetUser(BaseModel):
    user: str
    count: int


class FailedAuthResponse(BaseModel):
    hours: int
    total: int
    top_sources: list[_IPCount]
    hourly: list[_AlertPoint]
    unique_source_count: int
    external_source_count: int
    top_target_users: list[_TargetUser]


@router.get("/analytics/failed-auth", response_model=FailedAuthResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def failed_auth(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    since_trunc = since.replace(minute=0, second=0, microsecond=0)

    action_ph = ", ".join(["%s"] * len(_FAILED_AUTH_ACTIONS))
    if tid is None:
        tenant_clause = ""
        base_params: list = [since_trunc, *_FAILED_AUTH_ACTIONS]
    else:
        tenant_clause = "AND tenant_id = %s"
        base_params = [since_trunc, tid, *_FAILED_AUTH_ACTIONS]

    _rfc1918_not_clause = """NOT (
        source_ip LIKE '10.%' OR source_ip LIKE '192.168.%' OR
        source_ip LIKE '172.16.%' OR source_ip LIKE '172.17.%' OR
        source_ip LIKE '172.18.%' OR source_ip LIKE '172.19.%' OR
        source_ip LIKE '172.20.%' OR source_ip LIKE '172.21.%' OR
        source_ip LIKE '172.22.%' OR source_ip LIKE '172.23.%' OR
        source_ip LIKE '172.24.%' OR source_ip LIKE '172.25.%' OR
        source_ip LIKE '172.26.%' OR source_ip LIKE '172.27.%' OR
        source_ip LIKE '172.28.%' OR source_ip LIKE '172.29.%' OR
        source_ip LIKE '172.30.%' OR source_ip LIKE '172.31.%'
    )"""

    with db._connect() as conn:
        hourly_rows = conn.execute(
            f"""
            SELECT
                {_NORM_HOUR_EXPR} AS hour,
                COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action IN ({action_ph})
            GROUP BY hour
            ORDER BY hour
            """,
            base_params,
        ).fetchall()

        src_rows = conn.execute(
            f"""
            SELECT source_ip, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action IN ({action_ph})
              AND source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT 20
            """,
            base_params,
        ).fetchall()

        count_row = conn.execute(
            f"""
            SELECT
                COUNT(DISTINCT source_ip) AS unique_src,
                COUNT(DISTINCT CASE WHEN {_rfc1918_not_clause} THEN source_ip END) AS external_src
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action IN ({action_ph})
              AND source_ip IS NOT NULL
            """,
            base_params,
        ).fetchone()

        user_rows: list = []

    now_trunc = now.replace(minute=0, second=0, microsecond=0)
    n_buckets = int((now_trunc - since_trunc).total_seconds() // 3600) + 1
    all_hours = [
        (since_trunc + timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00Z")
        for i in range(n_buckets)
    ]
    hour_map: dict[str, int] = {r["hour"]: r["cnt"] for r in hourly_rows}
    hourly = [_AlertPoint(t=h, v=hour_map.get(h, 0)) for h in all_hours]
    total = sum(r["cnt"] for r in hourly_rows)
    top_sources = [_IPCount(ip=r["source_ip"], count=r["cnt"]) for r in src_rows]
    unique_source_count = count_row["unique_src"] or 0 if count_row else 0
    external_source_count = count_row["external_src"] or 0 if count_row else 0
    top_target_users: list[_TargetUser] = []

    return FailedAuthResponse(
        hours=hours,
        total=total,
        top_sources=top_sources,
        hourly=hourly,
        unique_source_count=unique_source_count,
        external_source_count=external_source_count,
        top_target_users=top_target_users,
    )


# ─── Source Health ────────────────────────────────────────────────────────────

class _SourceHealth(BaseModel):
    source_type: str
    last_seen: str | None
    age_minutes: float | None
    stale: bool


class SourceHealthResponse(BaseModel):
    sources: list[_SourceHealth]
    checked_at: str


@router.get("/analytics/source-health", response_model=SourceHealthResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def source_health(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)

    if tid is None:
        tenant_clause = ""
        params: list = [since]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since, tid]

    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT source_type, MAX(received_at) AS last_seen
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND source_type IS NOT NULL
            GROUP BY source_type
            ORDER BY last_seen DESC
            """,
            params,
        ).fetchall()

    sources = []
    for r in rows:
        ls = r["last_seen"]
        if ls is None:
            sources.append(_SourceHealth(source_type=r["source_type"], last_seen=None, age_minutes=None, stale=True))
            continue
        if isinstance(ls, str):
            try:
                from dateutil.parser import parse as _parse_dt
                ls_dt = _parse_dt(ls)
                if ls_dt.tzinfo is None:
                    ls_dt = ls_dt.replace(tzinfo=timezone.utc)
            except Exception as exc:
                logger.debug("source_health timestamp parse hatası [%s]: %s", r["source_type"], exc)
                sources.append(_SourceHealth(source_type=r["source_type"], last_seen=ls, age_minutes=None, stale=True))
                continue
        else:
            ls_dt = ls
            if ls_dt.tzinfo is None:
                ls_dt = ls_dt.replace(tzinfo=timezone.utc)
        age_min = (now - ls_dt).total_seconds() / 60
        sources.append(_SourceHealth(
            source_type=r["source_type"],
            last_seen=ls_dt.isoformat(),
            age_minutes=round(age_min, 1),
            stale=age_min > 15,
        ))

    return SourceHealthResponse(sources=sources, checked_at=now.isoformat())


# ─── DNS Analysis ─────────────────────────────────────────────────────────────

class _DnsEvent(BaseModel):
    source_ip: str | None
    message: str
    timestamp: str


class DnsAnalysisResponse(BaseModel):
    hours: int
    top_queried_destinations: list[_IPCount]
    nxdomain_count: int
    nxdomain_rate: float
    hourly_volume: list[_AlertPoint]
    unique_destinations: int
    high_entropy_count: int
    long_query_count: int
    anomaly_count: int
    high_entropy_domains: list[_DnsEvent]
    long_query_domains: list[_DnsEvent]
    nxdomain_top_sources: list[_IPCount]


@router.get("/analytics/dns-analysis", response_model=DnsAnalysisResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def dns_analysis(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    since_trunc = since.replace(minute=0, second=0, microsecond=0)

    if tid is None:
        tenant_clause = ""
        base_params: list = [since_trunc]
    else:
        tenant_clause = "AND tenant_id = %s"
        base_params = [since_trunc, tid]

    with db._connect() as conn:
        dns_params = [*base_params, "dns_query"]
        hourly_rows = conn.execute(
            f"""
            SELECT
                {_NORM_HOUR_EXPR} AS hour,
                COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
            GROUP BY hour
            ORDER BY hour
            """,
            dns_params,
        ).fetchall()

        top_rows = conn.execute(
            f"""
            SELECT destination_ip, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
              AND destination_ip IS NOT NULL
            GROUP BY destination_ip
            ORDER BY cnt DESC
            LIMIT %s
            """,
            [*base_params, "dns_query", limit],
        ).fetchall()

        nxdomain_row = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
              AND message LIKE %s
            """,
            [*base_params, "dns_query", "% → NXDOMAIN%"],
        ).fetchone()

        unique_row = conn.execute(
            f"""
            SELECT COUNT(DISTINCT destination_ip) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
              AND destination_ip IS NOT NULL
            """,
            dns_params,
        ).fetchone()

        high_entropy_row = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
              AND message LIKE %s
            """,
            [*base_params, "dns_query", "%[HIGH_ENTROPY:%"],
        ).fetchone()

        long_query_row = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
              AND message LIKE %s
            """,
            [*base_params, "dns_query", "%[LONG_QUERY:%"],
        ).fetchone()

        anomaly_row = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
            """,
            [*base_params, "dns_query_burst"],
        ).fetchone()

        high_entropy_rows = conn.execute(
            f"""
            SELECT source_ip, message, timestamp
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
              AND message LIKE %s
            ORDER BY received_at DESC
            LIMIT 20
            """,
            [*base_params, "dns_query", "%[HIGH_ENTROPY:%"],
        ).fetchall()

        long_query_rows = conn.execute(
            f"""
            SELECT source_ip, message, timestamp
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
              AND message LIKE %s
            ORDER BY received_at DESC
            LIMIT 20
            """,
            [*base_params, "dns_query", "%[LONG_QUERY:%"],
        ).fetchall()

        nxdomain_source_rows = conn.execute(
            f"""
            SELECT source_ip, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
              AND message LIKE %s
              AND source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT 10
            """,
            [*base_params, "dns_query", "% → NXDOMAIN%"],
        ).fetchall()

    now_trunc = now.replace(minute=0, second=0, microsecond=0)
    n_buckets = int((now_trunc - since_trunc).total_seconds() // 3600) + 1
    all_hours = [
        (since_trunc + timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00Z")
        for i in range(n_buckets)
    ]
    hour_map = {r["hour"]: r["cnt"] for r in hourly_rows}
    hourly_volume = [_AlertPoint(t=h, v=hour_map.get(h, 0)) for h in all_hours]
    total_dns = sum(r["cnt"] for r in hourly_rows)
    nxdomain_count = nxdomain_row["cnt"] if nxdomain_row else 0
    nxdomain_rate = round(nxdomain_count / total_dns * 100, 1) if total_dns > 0 else 0.0
    unique_destinations = unique_row["cnt"] if unique_row else 0
    top_queried = [_IPCount(ip=r["destination_ip"], count=r["cnt"]) for r in top_rows]

    return DnsAnalysisResponse(
        hours=hours,
        top_queried_destinations=top_queried,
        nxdomain_count=nxdomain_count,
        nxdomain_rate=nxdomain_rate,
        hourly_volume=hourly_volume,
        unique_destinations=unique_destinations,
        high_entropy_count=high_entropy_row["cnt"] if high_entropy_row else 0,
        long_query_count=long_query_row["cnt"] if long_query_row else 0,
        anomaly_count=anomaly_row["cnt"] if anomaly_row else 0,
        high_entropy_domains=[
            _DnsEvent(source_ip=r["source_ip"], message=r["message"], timestamp=str(r["timestamp"]))
            for r in high_entropy_rows
        ],
        long_query_domains=[
            _DnsEvent(source_ip=r["source_ip"], message=r["message"], timestamp=str(r["timestamp"]))
            for r in long_query_rows
        ],
        nxdomain_top_sources=[
            _IPCount(ip=r["source_ip"], count=r["cnt"])
            for r in nxdomain_source_rows
        ],
    )


# ─── TLS Fingerprints ─────────────────────────────────────────────────────────

_JA4_RE = re.compile(r'JA4=([a-z0-9_]+)', re.IGNORECASE)
_SNI_RE = re.compile(r'SSL/TLS\s+(\S+)', re.IGNORECASE)
_TLS_VERSION_MAP = {
    't13': 'TLS 1.3',
    't12': 'TLS 1.2',
    't11': 'TLS 1.1',
    't10': 'TLS 1.0',
}


class _TlsFingerprintItem(BaseModel):
    fingerprint: str
    count: int
    is_malicious: bool


class _TlsVersionItem(BaseModel):
    version: str
    count: int


class _TlsSniItem(BaseModel):
    sni: str
    count: int


class TlsFingerprintResponse(BaseModel):
    hours: int
    total_connections: int
    unique_count: int
    suspicious_count: int
    self_signed_count: int
    top_fingerprints: list[_TlsFingerprintItem]
    tls_version_dist: list[_TlsVersionItem]
    top_sni: list[_TlsSniItem]


@router.get("/analytics/tls-fingerprints", response_model=TlsFingerprintResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def tls_fingerprints(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    if tid is None:
        tenant_clause = ""
        params: list = [since]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since, tid]

    with db._connect() as conn:
        total_row = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action IN ('ssl_connection', 'tls_suspicious_fingerprint')
            """,
            params,
        ).fetchone()

        suspicious_row = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = 'tls_suspicious_fingerprint'
            """,
            params,
        ).fetchone()

        self_signed_row = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action IN ('ssl_connection', 'tls_suspicious_fingerprint')
              AND LOWER(message) LIKE %s
            """,
            [*params, '%self signed%'],
        ).fetchone()

        unique_row = conn.execute(
            f"""
            SELECT COUNT(DISTINCT message) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action IN ('ssl_connection', 'tls_suspicious_fingerprint')
              AND message IS NOT NULL
              AND LENGTH(TRIM(message)) > 0
            """,
            params,
        ).fetchone()

        detail_rows = conn.execute(
            f"""
            SELECT message, event_action, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action IN ('ssl_connection', 'tls_suspicious_fingerprint')
              AND message IS NOT NULL
              AND LENGTH(TRIM(message)) > 0
            GROUP BY message, event_action
            ORDER BY cnt DESC
            LIMIT 500
            """,
            params,
        ).fetchall()

    total_connections = total_row["cnt"] if total_row else 0
    suspicious_count = suspicious_row["cnt"] if suspicious_row else 0
    self_signed_count = self_signed_row["cnt"] if self_signed_row else 0
    unique_count = unique_row["cnt"] if unique_row else 0

    fp_counts: dict[str, tuple[int, bool]] = {}
    version_counts: dict[str, int] = defaultdict(int)
    sni_counts: dict[str, int] = defaultdict(int)

    for r in detail_rows:
        msg = r["message"] or ""
        cnt = r["cnt"]

        ja4_match = _JA4_RE.search(msg)
        if ja4_match:
            fp = ja4_match.group(1)
            is_malicious = '[KNOWN_MALWARE_JA' in msg
            existing_cnt, existing_mal = fp_counts.get(fp, (0, False))
            fp_counts[fp] = (existing_cnt + cnt, existing_mal or is_malicious)

            version_key = fp[:3].lower()
            version_label = _TLS_VERSION_MAP.get(version_key, 'Unknown')
            version_counts[version_label] += cnt

        sni_match = _SNI_RE.search(msg)
        if sni_match:
            sni = sni_match.group(1)
            if sni.lower() != 'unknown':
                sni_counts[sni] += cnt

    top_fingerprints = [
        _TlsFingerprintItem(fingerprint=fp, count=cnt, is_malicious=mal)
        for fp, (cnt, mal) in sorted(fp_counts.items(), key=lambda x: -x[1][0])
    ][:limit]

    tls_version_dist = [
        _TlsVersionItem(version=ver, count=cnt)
        for ver, cnt in sorted(version_counts.items(), key=lambda x: -x[1])
    ]

    top_sni = [
        _TlsSniItem(sni=sni, count=cnt)
        for sni, cnt in sorted(sni_counts.items(), key=lambda x: -x[1])
    ][:10]

    return TlsFingerprintResponse(
        hours=hours,
        total_connections=total_connections,
        unique_count=unique_count,
        suspicious_count=suspicious_count,
        self_signed_count=self_signed_count,
        top_fingerprints=top_fingerprints,
        tls_version_dist=tls_version_dist,
        top_sni=top_sni,
    )


# ─── Beaconing Summary ────────────────────────────────────────────────────────

_IAT_RE = re.compile(r'mean_iat=(\d+\.?\d*)s')
_JITTER_RE = re.compile(r'jitter=(\d+\.?\d*)%')
_CONN_RE = re.compile(r'(\d+)\s+conn')


def _parse_beaconing_message(msg: str) -> tuple[float | None, float | None, int | None]:
    iat_match = _IAT_RE.search(msg)
    jitter_match = _JITTER_RE.search(msg)
    conn_match = _CONN_RE.search(msg)

    mean_iat = float(iat_match.group(1)) if iat_match else None
    jitter = round(float(jitter_match.group(1)) / 100, 6) if jitter_match else None
    conn_count = int(conn_match.group(1)) if conn_match else None

    return mean_iat, jitter, conn_count


class _BeaconingDetection(BaseModel):
    source_ip: str
    destination_ip: str
    destination_port: int | None = None
    network_protocol: str | None = None
    mean_iat: float | None = None
    jitter: float | None = None
    conn_count: int | None = None
    message: str
    detected_at: str


class BeaconingSummaryResponse(BaseModel):
    hours: int
    detections: list[_BeaconingDetection]
    total: int


@router.get("/analytics/beaconing-summary", response_model=BeaconingSummaryResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def beaconing_summary(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    if tid is None:
        tenant_clause = ""
        params: list = [since, "c2_beaconing"]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since, tid, "c2_beaconing"]

    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT source_ip, destination_ip, destination_port,
                   network_protocol, message, received_at
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
            ORDER BY received_at DESC
            LIMIT 200
            """,
            params,
        ).fetchall()

    detections = []
    for r in rows:
        msg = r["message"] or ""
        mean_iat, jitter, conn_count = _parse_beaconing_message(msg)
        detections.append(_BeaconingDetection(
            source_ip=r["source_ip"] or "",
            destination_ip=r["destination_ip"] or "",
            destination_port=r["destination_port"],
            network_protocol=r["network_protocol"],
            mean_iat=mean_iat,
            jitter=jitter,
            conn_count=conn_count,
            message=msg,
            detected_at=str(r["received_at"]),
        ))

    return BeaconingSummaryResponse(hours=hours, detections=detections, total=len(detections))


# ─── Threat Summary ───────────────────────────────────────────────────────────

class _ThreatSource(BaseModel):
    ip: str
    count: int
    last_seen: str
    composite_score: int
    country_code: str
    isp: str
    feodo_listed: bool
    feodo_malware: str
    threatfox_score: int
    threatfox_malware: str
    greynoise_noise: bool
    greynoise_classification: str


class _CountryCount(BaseModel):
    country_code: str
    ip_count: int


class ThreatSummaryResponse(BaseModel):
    hours: int
    top_sources: list[_ThreatSource]
    total_alerts: int
    critical_count: int
    high_risk_count: int
    country_distribution: list[_CountryCount]


@router.get("/analytics/threat-summary", response_model=ThreatSummaryResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def threat_summary(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    if tid is None:
        tenant_clause = ""
        count_params: list = [since]
        critical_params: list = [since, "critical"]
    else:
        tenant_clause = "AND tenant_id = %s"
        count_params = [since, tid]
        critical_params = [since, tid, "critical"]

    with db._connect() as conn:
        total_row = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM alerts
            WHERE triggered_at >= %s
              {tenant_clause}
            """,
            count_params,
        ).fetchone()

        critical_row = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM alerts
            WHERE triggered_at >= %s
              {tenant_clause}
              AND severity = %s
            """,
            critical_params,
        ).fetchone()

        src_rows = conn.execute(
            f"""
            SELECT
                n.source_ip,
                COUNT(*) AS cnt,
                MAX(n.received_at) AS last_seen,
                COALESCE(t.composite_score, 0) AS composite_score,
                COALESCE(t.country_code, '') AS country_code,
                COALESCE(t.isp, '') AS isp,
                COALESCE(t.feodo_listed, false) AS feodo_listed,
                COALESCE(t.feodo_malware, '') AS feodo_malware,
                COALESCE(t.threatfox_score, 0) AS threatfox_score,
                COALESCE(t.threatfox_malware, '') AS threatfox_malware,
                COALESCE(t.greynoise_noise, false) AS greynoise_noise,
                COALESCE(t.greynoise_classification, '') AS greynoise_classification
            FROM normalized_logs n
            LEFT JOIN threat_intel_cache t ON t.ip = n.source_ip
            WHERE n.received_at >= %s
              {tenant_clause}
              AND n.tags LIKE %s
              AND n.source_ip IS NOT NULL
            GROUP BY n.source_ip, t.composite_score, t.country_code, t.isp,
                     t.feodo_listed, t.feodo_malware, t.threatfox_score, t.threatfox_malware,
                     t.greynoise_noise, t.greynoise_classification
            ORDER BY composite_score DESC, cnt DESC
            LIMIT %s
            """,
            [*count_params, "%threat_intel%", limit],
        ).fetchall()

        country_rows = conn.execute(
            f"""
            SELECT
                COALESCE(t.country_code, 'XX') AS country_code,
                COUNT(DISTINCT n.source_ip) AS ip_count
            FROM normalized_logs n
            LEFT JOIN threat_intel_cache t ON t.ip = n.source_ip
            WHERE n.received_at >= %s
              {tenant_clause}
              AND n.tags LIKE %s
              AND n.source_ip IS NOT NULL
            GROUP BY COALESCE(t.country_code, 'XX')
            ORDER BY ip_count DESC
            LIMIT 20
            """,
            [*count_params, "%threat_intel%"],
        ).fetchall()

        high_risk_row = conn.execute(
            f"""
            SELECT COUNT(DISTINCT n.source_ip) AS cnt
            FROM normalized_logs n
            LEFT JOIN threat_intel_cache t ON t.ip = n.source_ip
            WHERE n.received_at >= %s
              {tenant_clause}
              AND n.tags LIKE %s
              AND n.source_ip IS NOT NULL
              AND COALESCE(t.composite_score, 0) >= 70
            """,
            [*count_params, "%threat_intel%"],
        ).fetchone()

    total_alerts = total_row["cnt"] if total_row else 0
    critical_count = critical_row["cnt"] if critical_row else 0
    high_risk_count = high_risk_row["cnt"] if high_risk_row else 0

    top_sources = [
        _ThreatSource(
            ip=r["source_ip"],
            count=r["cnt"],
            last_seen=str(r["last_seen"]) if r["last_seen"] else "",
            composite_score=r["composite_score"],
            country_code=r["country_code"],
            isp=r["isp"],
            feodo_listed=bool(r["feodo_listed"]),
            feodo_malware=r["feodo_malware"] or "",
            threatfox_score=r["threatfox_score"] or 0,
            threatfox_malware=r["threatfox_malware"] or "",
            greynoise_noise=bool(r["greynoise_noise"]),
            greynoise_classification=r["greynoise_classification"] or "",
        )
        for r in src_rows
    ]

    country_distribution = [
        _CountryCount(country_code=r["country_code"], ip_count=r["ip_count"])
        for r in country_rows
    ]

    return ThreatSummaryResponse(
        hours=hours,
        top_sources=top_sources,
        total_alerts=total_alerts,
        critical_count=critical_count,
        high_risk_count=high_risk_count,
        country_distribution=country_distribution,
    )


# ─── Kill Chain Timeline ──────────────────────────────────────────────────────

_STAGE_LABELS: dict[str, str] = {
    "recon":    "Keşif",
    "weaponize": "Silahlanma",
    "access":   "Erişim",
    "lateral":  "Yanal Hareket",
}

_FULL_THRESHOLD = 3


class _ChainEvent(BaseModel):
    stage: str
    label: str
    occurred_at: str


class _ChainRow(BaseModel):
    source_ip: str
    chain_type: str
    stage_count: int
    events: list[_ChainEvent]
    first_seen: str
    last_seen: str


class KillChainTimelineResponse(BaseModel):
    hours: int
    window_start: str
    window_end: str
    rows: list[_ChainRow]


@router.get("/analytics/kill-chain-timeline", response_model=KillChainTimelineResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def kill_chain_timeline(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=50),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    if tid is None:
        tenant_clause = ""
        params: list = [since]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since, tid]

    with db._connect() as conn:
        raw_rows = conn.execute(
            f"""
            SELECT source_ip, stage, occurred_at
            FROM attack_chain_state
            WHERE occurred_at >= %s
              {tenant_clause}
            ORDER BY occurred_at
            """,
            params,
        ).fetchall()

    ip_events: dict[str, list[dict]] = defaultdict(list)
    for row in raw_rows:
        occ_raw = row["occurred_at"]
        try:
            occ_dt = _to_dt(occ_raw)
            if occ_dt.tzinfo is None:
                occ_dt = occ_dt.replace(tzinfo=timezone.utc)
            occ = occ_dt.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
        except (ValueError, TypeError):
            occ = str(occ_raw)
        ip_events[row["source_ip"]].append({"stage": row["stage"], "occurred_at": occ})

    chain_rows: list[_ChainRow] = []
    for source_ip, events in ip_events.items():
        unique_stages = {e["stage"] for e in events}
        stage_count = len(unique_stages)
        chain_type = "FULL_ATTACK_CHAIN" if stage_count >= _FULL_THRESHOLD else "PARTIAL_ATTACK_CHAIN"
        dt_times = [_to_dt(e["occurred_at"]) for e in events]
        first_seen = min(dt_times).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
        last_seen = max(dt_times).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
        chain_rows.append(_ChainRow(
            source_ip=source_ip,
            chain_type=chain_type,
            stage_count=stage_count,
            events=[
                _ChainEvent(
                    stage=e["stage"],
                    label=_STAGE_LABELS.get(e["stage"], e["stage"]),
                    occurred_at=e["occurred_at"],
                )
                for e in events
            ],
            first_seen=first_seen,
            last_seen=last_seen,
        ))

    chain_rows.sort(key=lambda r: (-r.stage_count, r.source_ip))

    return KillChainTimelineResponse(
        hours=hours,
        window_start=since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        window_end=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        rows=chain_rows[:limit],
    )


# ─── East-West Connection Matrix ─────────────────────────────────────────────

class _MatrixRow(BaseModel):
    src: str
    dst: str
    count: int


class EastWestMatrixResponse(BaseModel):
    hours: int
    rows: list[_MatrixRow]
    max_count: int
    unique_pairs: int


@router.get("/analytics/east-west-matrix", response_model=EastWestMatrixResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def east_west_matrix(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    if tid is None:
        tenant_clause = ""
        params: list = [since]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since, tid]

    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT source_ip AS src, destination_ip AS dst, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND source_ip IS NOT NULL
              AND destination_ip IS NOT NULL
              AND {_RFC1918_LIKE}
              AND {_RFC1918_DST_LIKE}
            GROUP BY src, dst
            ORDER BY cnt DESC
            LIMIT %s
            """,
            [*params, limit],
        ).fetchall()

    matrix_rows = [_MatrixRow(src=r["src"], dst=r["dst"], count=r["cnt"]) for r in rows]
    max_count = matrix_rows[0].count if matrix_rows else 0

    return EastWestMatrixResponse(
        hours=hours,
        rows=matrix_rows,
        max_count=max_count,
        unique_pairs=len(matrix_rows),
    )


# ─── Asset Risk Heatmap ───────────────────────────────────────────────────────

_ASSET_SEV_WEIGHTS: dict[str, int] = {
    "critical": 40, "high": 15, "warning": 5, "info": 1,
}
_ASSET_SEV_RANK: dict[str, int] = {
    "critical": 4, "high": 3, "warning": 2, "info": 1,
}

# Kill-chain event_action → danger weight (recon=2, weaponize=8, lateral/C2=20)
_CHAIN_ACTION_WEIGHTS: dict[str, int] = {
    "port_scan": 2, "dns_anomaly": 2, "arp_attack": 2, "web_scan_detected": 2,
    "anomaly_detected": 2, "asset_anomaly_detected": 2, "arp_spoof": 2,
    "zeek_port": 2, "dns_query": 2, "icmp_flood": 2, "tls_suspicious": 2,
    "ssl_self": 2, "ssl_cert": 2, "firewall_beacon": 2, "firewall_ddos": 2,
    "network_connection_fl": 2, "anomaly_cluster": 2, "coordinated": 2,
    "suricata_alert": 2, "suricata_anomaly": 2, "multi_source_attack_detected": 2,
    "ssh_failure": 8, "windows_logon_failure": 8, "windows_brute_force": 8,
    "brute_force": 8, "ssh_brute_force": 8, "windows_pass_the_hash": 8,
    "ssh_target": 8, "web_auth": 8, "brute_force_detected": 8,
    "lateral_movement": 20, "windows_lateral_movement": 20, "windows_lateral": 20,
    "ssh_lateral": 20, "dns_c2": 20, "dns_tunnel": 20, "ftp_exfil": 20,
    "c2_beaconing": 20,
    "FULL_ATTACK_CHAIN": 50, "PARTIAL_ATTACK_CHAIN": 25,
}
_CHAIN_ACTIONS: tuple[str, ...] = tuple(_CHAIN_ACTION_WEIGHTS.keys())
_CHAIN_PH = ", ".join(["%s"] * len(_CHAIN_ACTIONS))


class AssetRiskEntry(BaseModel):
    ip: str
    activity_score: float
    chain_score: float
    block_score: float
    total_score: float
    is_blocked: bool
    top_severity: str | None
    event_count: int


class AssetRiskResponse(BaseModel):
    hours: int
    limit: int
    assets: list[AssetRiskEntry]


@router.get("/analytics/asset-risk", response_model=AssetRiskResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def asset_risk(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=20, ge=1, le=50),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    if tid is None:
        tenant_clause = ""
        base_params: list = [since]
        chain_params: list = [since, *_CHAIN_ACTIONS]
        blocked_tenant_clause = ""
        blocked_params: list = [now]
    else:
        tenant_clause = "AND tenant_id = %s"
        base_params = [since, tid]
        chain_params = [since, *_CHAIN_ACTIONS, tid]
        blocked_tenant_clause = "AND tenant_id = %s"
        blocked_params = [now, tid]

    with db._connect() as conn:
        act_rows = conn.execute(
            f"""
            SELECT source_ip, severity, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              AND source_ip IS NOT NULL
              AND {_RFC1918_LIKE}
              {tenant_clause}
            GROUP BY source_ip, severity
            """,
            base_params,
        ).fetchall()

        chain_rows = conn.execute(
            f"""
            SELECT source_ip, event_action, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              AND source_ip IS NOT NULL
              AND {_RFC1918_LIKE}
              AND event_action IN ({_CHAIN_PH})
              {tenant_clause}
            GROUP BY source_ip, event_action
            """,
            chain_params,
        ).fetchall()

        blocked_rows = conn.execute(
            f"""
            SELECT ip FROM blocked_ips
            WHERE is_active = 1
              AND (expires_at IS NULL OR expires_at > %s)
              {blocked_tenant_clause}
            """,
            blocked_params,
        ).fetchall()

    blocked_set = {r["ip"] for r in blocked_rows}

    ip_sev: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    ip_total: dict[str, int] = defaultdict(int)
    for r in act_rows:
        ip = r["source_ip"]
        ip_sev[ip][r["severity"]] += r["cnt"]
        ip_total[ip] += r["cnt"]

    ip_chain_raw: dict[str, float] = defaultdict(float)
    for r in chain_rows:
        ip = r["source_ip"]
        ip_chain_raw[ip] += _CHAIN_ACTION_WEIGHTS.get(r["event_action"], 0) * r["cnt"]

    all_ips = set(ip_sev.keys()) | set(ip_chain_raw.keys())

    entries: list[AssetRiskEntry] = []
    for ip in all_ips:
        sev_counts = ip_sev[ip]
        act_raw = sum(
            _ASSET_SEV_WEIGHTS.get(sev, 0) * cnt for sev, cnt in sev_counts.items()
        )
        activity_score = min(100.0, float(act_raw))
        chain_score = min(100.0, float(ip_chain_raw.get(ip, 0.0)))
        is_blocked = ip in blocked_set
        block_score = 100.0 if is_blocked else 0.0
        total_score = round(activity_score * 0.5 + chain_score * 0.3 + block_score * 0.2, 1)

        top_severity: str | None = None
        if sev_counts:
            top_severity = max(sev_counts, key=lambda s: _ASSET_SEV_RANK.get(s, 0))

        entries.append(AssetRiskEntry(
            ip=ip,
            activity_score=round(activity_score, 1),
            chain_score=round(chain_score, 1),
            block_score=block_score,
            total_score=total_score,
            is_blocked=is_blocked,
            top_severity=top_severity,
            event_count=ip_total.get(ip, 0),
        ))

    entries.sort(key=lambda e: e.total_score, reverse=True)

    return AssetRiskResponse(hours=hours, limit=limit, assets=entries[:limit])


# ─── MTTD / MTTR ─────────────────────────────────────────────────���───────────
# SLA hedefleri: SANS 2023 Incident Response Survey + Prophet Security benchmarks
# Critical <15dk MTTD / <60dk MTTR; High <60dk/<120dk; Warning <4s/<8s
_SLA_MTTD: dict[str, int] = {
    "critical": 15,
    "high":     60,
    "warning":  240,
    "info":     1440,
}
_SLA_MTTR: dict[str, int] = {
    "critical": 60,
    "high":     120,
    "warning":  480,
    "info":     1440,
}
_MAX_VALID_MINUTES = 60 * 24 * 30  # 30 gün üstü outlier


def _parse_dt(s) -> datetime | None:
    if s is None:
        return None
    if isinstance(s, datetime):
        return s
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _safe_diff_minutes(end: datetime | None, start: datetime | None) -> float | None:
    if end is None or start is None:
        return None
    delta = (end - start).total_seconds() / 60
    if delta < 0 or delta > _MAX_VALID_MINUTES:
        return None  # negatif veya aşırı büyük — veri kalitesi sorunu, atla
    return delta


class _DayPoint(BaseModel):
    date: str
    mttd_minutes: float
    mttr_minutes: float
    count: int


class _SeverityBreakdown(BaseModel):
    severity: str
    count: int
    avg_mttd_minutes: float | None
    avg_mttr_minutes: float | None
    mttd_sla_pct: float
    mttr_sla_pct: float
    mttd_target_minutes: int
    mttr_target_minutes: int


class MttdMttrResponse(BaseModel):
    days: int
    total_incidents: int
    resolved_incidents: int
    acknowledged_incidents: int
    resolution_rate: float
    overall_mttd_minutes: float | None
    overall_mttr_minutes: float | None
    trend: list[_DayPoint]
    by_severity: list[_SeverityBreakdown]


@router.get("/analytics/mttd-mttr", response_model=MttdMttrResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def mttd_mttr(
    request: Request,
    response: Response,
    days: int = Query(default=30, ge=1, le=90),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    if tid is None:
        tenant_clause = ""
        params: list = [since]
    else:
        tenant_clause = "AND tenant_id = %s"
        params = [since, tid]

    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT created_at, acknowledged_at, resolved_at, severity, status
            FROM incidents
            WHERE created_at >= %s
              {tenant_clause}
            ORDER BY created_at DESC
            """,
            params,
        ).fetchall()

    total = len(rows)
    resolved = sum(1 for r in rows if r["status"] in ("resolved", "closed"))
    acked = sum(1 for r in rows if r["acknowledged_at"] is not None)
    resolution_rate = round(resolved / total * 100, 1) if total > 0 else 0.0

    mttd_vals: list[float] = []
    mttr_vals: list[float] = []
    sev_data: dict[str, dict[str, list[float]]] = defaultdict(lambda: {"mttd": [], "mttr": []})
    day_data: dict[str, dict[str, list[float]]] = defaultdict(lambda: {"mttd": [], "mttr": []})

    for r in rows:
        created = _parse_dt(r["created_at"])
        mttd = _safe_diff_minutes(_parse_dt(r["acknowledged_at"]), created)
        mttr = _safe_diff_minutes(_parse_dt(r["resolved_at"]), created)
        sev = r["severity"] or "info"
        day_key = created.date().isoformat() if created else None

        if mttd is not None:
            mttd_vals.append(mttd)
            sev_data[sev]["mttd"].append(mttd)
            if day_key:
                day_data[day_key]["mttd"].append(mttd)
        if mttr is not None:
            mttr_vals.append(mttr)
            sev_data[sev]["mttr"].append(mttr)
            if day_key:
                day_data[day_key]["mttr"].append(mttr)

    overall_mttd = round(sum(mttd_vals) / len(mttd_vals), 1) if mttd_vals else None
    overall_mttr = round(sum(mttr_vals) / len(mttr_vals), 1) if mttr_vals else None

    all_days = [
        (since.date() + timedelta(days=i)).isoformat()
        for i in range(days + 1)
    ]
    trend: list[_DayPoint] = []
    for d in all_days:
        dd = day_data.get(d, {"mttd": [], "mttr": []})
        trend.append(_DayPoint(
            date=d,
            mttd_minutes=round(sum(dd["mttd"]) / len(dd["mttd"]), 1) if dd["mttd"] else 0.0,
            mttr_minutes=round(sum(dd["mttr"]) / len(dd["mttr"]), 1) if dd["mttr"] else 0.0,
            count=max(len(dd["mttd"]), len(dd["mttr"])),
        ))

    by_severity: list[_SeverityBreakdown] = []
    for sev in ("critical", "high", "warning", "info"):
        count_sev = sum(1 for r in rows if (r["severity"] or "info") == sev)
        if count_sev == 0:
            continue
        dd = sev_data.get(sev, {"mttd": [], "mttr": []})
        m_list = dd["mttd"]
        r_list = dd["mttr"]
        t_mttd = _SLA_MTTD[sev]
        t_mttr = _SLA_MTTR[sev]
        by_severity.append(_SeverityBreakdown(
            severity=sev,
            count=count_sev,
            avg_mttd_minutes=round(sum(m_list) / len(m_list), 1) if m_list else None,
            avg_mttr_minutes=round(sum(r_list) / len(r_list), 1) if r_list else None,
            mttd_sla_pct=round(sum(1 for v in m_list if v <= t_mttd) / len(m_list) * 100, 1) if m_list else 0.0,
            mttr_sla_pct=round(sum(1 for v in r_list if v <= t_mttr) / len(r_list) * 100, 1) if r_list else 0.0,
            mttd_target_minutes=t_mttd,
            mttr_target_minutes=t_mttr,
        ))

    return MttdMttrResponse(
        days=days,
        total_incidents=total,
        resolved_incidents=resolved,
        acknowledged_incidents=acked,
        resolution_rate=resolution_rate,
        overall_mttd_minutes=overall_mttd,
        overall_mttr_minutes=overall_mttr,
        trend=trend,
        by_severity=by_severity,
    )


# ─── Log Volume ───────────────────────────────────────────────────────────────

class _LogPoint(BaseModel):
    t: str
    v: int


class LogVolumeResponse(BaseModel):
    hours: int
    bucket_minutes: int
    series: dict[str, list[_LogPoint]]


@router.get("/analytics/log-volume", response_model=LogVolumeResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def log_volume(
    request: Request,
    response: Response,
    hours: int = Query(default=24, ge=1, le=168),
    source_type: str = Query(default=None),
    event_category: str = Query(default=None),
    current_user: User = Depends(get_current_user),
):
    tid = tenant_scope(current_user)
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    bm = _bucket_minutes(hours)
    since_hour = since.replace(minute=0, second=0, microsecond=0)
    now_hour = now.replace(minute=0, second=0, microsecond=0)

    filters = ["timestamp >= %s", "timestamp <= %s"]
    params: list = [since_hour, now]
    if tid is not None:
        filters.append("tenant_id = %s")
        params.append(tid)
    if source_type:
        filters.append("source_type = %s")
        params.append(source_type)
    if event_category:
        filters.append("event_category = %s")
        params.append(event_category)

    where = " AND ".join(filters)
    _sev_ph = ", ".join(["%s"] * len(_SEVERITY_LEVELS))
    params.extend(_SEVERITY_LEVELS)

    _log_hour_expr = "to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD\"T\"HH24:00:00\"Z\"')"
    with db._connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
                {_log_hour_expr} AS hour,
                COALESCE(severity, 'info') AS severity,
                COUNT(*) AS cnt
            FROM normalized_logs
            WHERE {where}
              AND COALESCE(severity, 'info') IN ({_sev_ph})
            GROUP BY hour, severity
            ORDER BY hour
            """,
            params,
        ).fetchall()

    n_hours = int((now_hour - since_hour).total_seconds() // 3600) + 1
    all_hours = [
        (since_hour + timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00Z")
        for i in range(n_hours)
    ]

    hour_sev: dict[str, dict[str, int]] = {h: {s: 0 for s in _SEVERITY_LEVELS} for h in all_hours}
    for r in rows:
        h = r["hour"]
        if h in hour_sev:
            hour_sev[h][r["severity"]] = r["cnt"]

    if bm <= 60:
        all_buckets = all_hours
        bucket: dict[str, dict[str, int]] = hour_sev
    else:
        step_hours = bm // 60
        merged: dict[str, dict[str, int]] = {}
        for i, h in enumerate(all_hours):
            group_key = all_hours[(i // step_hours) * step_hours]
            if group_key not in merged:
                merged[group_key] = {s: 0 for s in _SEVERITY_LEVELS}
            for sev in _SEVERITY_LEVELS:
                merged[group_key][sev] += hour_sev[h][sev]
        all_buckets = list(merged.keys())
        bucket = merged

    series: dict[str, list[_LogPoint]] = {
        sev: [_LogPoint(t=b, v=bucket[b][sev]) for b in all_buckets]
        for sev in _SEVERITY_LEVELS
    }
    return LogVolumeResponse(hours=hours, bucket_minutes=bm, series=series)


# ─── Log Facets ───────────────────────────────────────────────────────────────

class _FacetItem(BaseModel):
    key: str
    count: int


class LogFacetsResponse(BaseModel):
    hours: int
    total: int
    sources: list[_FacetItem]
    categories: list[_FacetItem]
    severities: list[_FacetItem]


@router.get("/analytics/log-facets", response_model=LogFacetsResponse)
@limiter.limit("30/minute", key_func=_auth_key)
def log_facets(
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
        base_params: list = [since, now]
    else:
        tenant_clause = "AND tenant_id = %s"
        base_params = [since, now, tid]

    with db._connect() as conn:
        src_rows = conn.execute(
            f"""
            SELECT source_type AS k, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE timestamp >= %s AND timestamp <= %s {tenant_clause}
              AND source_type IS NOT NULL AND source_type != ''
            GROUP BY source_type ORDER BY cnt DESC LIMIT 20
            """,
            base_params,
        ).fetchall()

        cat_rows = conn.execute(
            f"""
            SELECT event_category AS k, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE timestamp >= %s AND timestamp <= %s {tenant_clause}
              AND event_category IS NOT NULL AND event_category != ''
            GROUP BY event_category ORDER BY cnt DESC LIMIT 20
            """,
            base_params,
        ).fetchall()

        sev_rows = conn.execute(
            f"""
            SELECT COALESCE(severity, 'info') AS k, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE timestamp >= %s AND timestamp <= %s {tenant_clause}
            GROUP BY k ORDER BY cnt DESC
            """,
            base_params,
        ).fetchall()

        total_row = conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM normalized_logs
            WHERE timestamp >= %s AND timestamp <= %s {tenant_clause}
            """,
            base_params,
        ).fetchone()

    total = total_row["cnt"] if total_row else 0
    return LogFacetsResponse(
        hours=hours,
        total=total,
        sources=[_FacetItem(key=r["k"], count=r["cnt"]) for r in src_rows],
        categories=[_FacetItem(key=r["k"], count=r["cnt"]) for r in cat_rows],
        severities=[_FacetItem(key=r["k"], count=r["cnt"]) for r in sev_rows],
    )
