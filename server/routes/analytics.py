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

    if tid is None:
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


# ─── Alert Volume ─────────────────────────────────────────────────────────────

_SEVERITY_LEVELS = ("critical", "high", "warning", "info")


def _bucket_minutes(hours: int) -> int:
    if hours <= 6:
        return 15
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
        step_hours = bm // 60  # 240min → 4h steps; 15min → treat as 1h in SQLite
        if bm < 60:
            # 15-minute granularity: keep hourly buckets (SQLite-compatible)
            all_buckets = all_hours
            bucket = hour_sev
        else:
            # 4-hour granularity: merge groups of 4 hours
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
    OR source_ip LIKE '127.%%'
    OR source_ip LIKE '169.254.%%'
    OR source_ip LIKE 'fc%%'
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
    OR destination_ip LIKE '127.%%'
    OR destination_ip LIKE '169.254.%%'
    OR destination_ip LIKE 'fc%%'
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


class FailedAuthResponse(BaseModel):
    hours: int
    total: int
    top_sources: list[_IPCount]
    hourly: list[_AlertPoint]


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

    return FailedAuthResponse(hours=hours, total=total, top_sources=top_sources, hourly=hourly)


# ─── DNS Analysis ─────────────────────────────────────────────────────────────

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
            [*base_params, "dns_query", "%NXDOMAIN%"],
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
    )


# ─── TLS Fingerprints ─────────────────────────────────────────────────────────

class _TlsFingerprint(BaseModel):
    fingerprint: str
    count: int


class TlsFingerprintResponse(BaseModel):
    hours: int
    top_fingerprints: list[_TlsFingerprint]
    unique_count: int


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
        top_rows = conn.execute(
            f"""
            SELECT message, COUNT(*) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
              AND message IS NOT NULL
              AND LENGTH(TRIM(message)) > 0
            GROUP BY message
            ORDER BY cnt DESC
            LIMIT %s
            """,
            [*params, "tls_connection", limit],
        ).fetchall()

        unique_row = conn.execute(
            f"""
            SELECT COUNT(DISTINCT message) AS cnt
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
              AND message IS NOT NULL
              AND LENGTH(TRIM(message)) > 0
            """,
            [*params, "tls_connection"],
        ).fetchone()

    top_fingerprints = [
        _TlsFingerprint(fingerprint=r["message"], count=r["cnt"])
        for r in top_rows
    ]
    unique_count = unique_row["cnt"] if unique_row else 0

    return TlsFingerprintResponse(
        hours=hours,
        top_fingerprints=top_fingerprints,
        unique_count=unique_count,
    )


# ─── Beaconing Summary ────────────────────────────────────────────────────────

class _BeaconingDetection(BaseModel):
    source_ip: str
    destination_ip: str
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
            SELECT source_ip, destination_ip, message, received_at
            FROM normalized_logs
            WHERE received_at >= %s
              {tenant_clause}
              AND event_action = %s
            ORDER BY received_at DESC
            LIMIT 200
            """,
            params,
        ).fetchall()

    detections = [
        _BeaconingDetection(
            source_ip=r["source_ip"] or "",
            destination_ip=r["destination_ip"] or "",
            message=r["message"],
            detected_at=r["received_at"],
        )
        for r in rows
    ]

    return BeaconingSummaryResponse(hours=hours, detections=detections, total=len(detections))


# ─── Threat Summary ───────────────────────────────────────────────────────────

class _ThreatSource(BaseModel):
    ip: str
    count: int
    last_seen: str
    composite_score: int
    country_code: str
    isp: str


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
                COALESCE(t.isp, '') AS isp
            FROM normalized_logs n
            LEFT JOIN threat_intel_cache t ON t.ip = n.source_ip
            WHERE n.received_at >= %s
              {tenant_clause}
              AND n.tags LIKE %s
              AND n.source_ip IS NOT NULL
            GROUP BY n.source_ip, t.composite_score, t.country_code, t.isp
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
        occ = row["occurred_at"]
        if not isinstance(occ, str):
            occ = occ.isoformat()
        ip_events[row["source_ip"]].append({"stage": row["stage"], "occurred_at": occ})

    chain_rows: list[_ChainRow] = []
    for source_ip, events in ip_events.items():
        unique_stages = {e["stage"] for e in events}
        stage_count = len(unique_stages)
        chain_type = "FULL_ATTACK_CHAIN" if stage_count >= _FULL_THRESHOLD else "PARTIAL_ATTACK_CHAIN"
        times = [e["occurred_at"] for e in events]
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
            first_seen=min(times),
            last_seen=max(times),
        ))

    chain_rows.sort(key=lambda r: (-r.stage_count, r.source_ip))

    return KillChainTimelineResponse(
        hours=hours,
        window_start=since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        window_end=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        rows=chain_rows[:limit],
    )
