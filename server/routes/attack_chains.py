"""
NetGuard — Kill Chain / Attack Chain endpoint'leri

GET /api/v1/attack-chains/active   → In-memory aktif zincirler (son 30 dk)
GET /api/v1/attack-chains/history  → DB'deki kill chain olayları
GET /api/v1/attack-chains/stats    → Kill chain istatistikleri
"""

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Query
from server.auth import get_current_user, User, tenant_scope
from server.attack_chain import attack_chain_tracker, STAGE_LABELS
import server.database as _db_mod

router = APIRouter()

CHAIN_RULE_IDS = {"full_attack_chain", "partial_attack_chain"}


@router.get("/attack-chains/active")
def active_chains(current_user: User = Depends(get_current_user)):
    """Son 30 dakikadaki in-memory aktif saldırı zincirlerini döner."""
    raw = attack_chain_tracker.get_chains()
    chains = []
    for src_ip, stage_counts in raw.items():
        stage_count = len(stage_counts)
        severity = "critical" if stage_count >= 3 else "warning"
        chains.append({
            "src_ip":      src_ip,
            "stages":      stage_counts,
            "stage_labels": {s: STAGE_LABELS.get(s, s) for s in stage_counts},
            "stage_count": stage_count,
            "severity":    severity,
            "chain_type":  "FULL_ATTACK_CHAIN" if stage_count >= 3 else "PARTIAL_ATTACK_CHAIN",
        })
    chains.sort(key=lambda c: (-c["stage_count"], c["src_ip"]))
    return {"count": len(chains), "chains": chains}


@router.get("/attack-chains/history")
def chain_history(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
):
    """DB'deki full/partial attack chain korelasyon olaylarını döner."""
    db = _db_mod.db
    tid = tenant_scope(current_user)
    all_events = []
    for rule_id in CHAIN_RULE_IDS:
        events = db.get_correlated_events(rule_id=rule_id, limit=limit, tenant_id=tid)
        all_events.extend(events)
    all_events.sort(key=lambda e: e.created_at, reverse=True)
    return {
        "count": len(all_events),
        "events": [e.model_dump(mode="json") for e in all_events[:limit]],
    }


@router.get("/attack-chains/stats")
def chain_stats(current_user: User = Depends(get_current_user)):
    """Kill chain istatistikleri: bugün, aktif IP, kritik sayısı."""
    db = _db_mod.db
    tid = tenant_scope(current_user)

    since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    all_events_24h = []
    for rule_id in CHAIN_RULE_IDS:
        events = db.get_correlated_events(rule_id=rule_id, limit=500, tenant_id=tid)
        all_events_24h.extend(
            e for e in events
            if e.created_at.isoformat() >= since_24h
        )

    active = attack_chain_tracker.get_chains()
    stage_dist: dict[str, int] = {}
    for stage_counts in active.values():
        for stage, count in stage_counts.items():
            stage_dist[stage] = stage_dist.get(stage, 0) + count

    return {
        "active_ips":         len(active),
        "chains_24h":         len(all_events_24h),
        "critical_24h":       sum(1 for e in all_events_24h if e.severity == "critical"),
        "unique_ips_24h":     len({e.group_value for e in all_events_24h}),
        "stage_distribution": stage_dist,
    }
