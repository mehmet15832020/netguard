"""
NetGuard Server — MITRE ATT&CK Endpoints

GET /api/v1/mitre/coverage  → Hangi kurallar hangi tekniği/taktiği karşılıyor
GET /api/v1/mitre/heatmap   → ATT&CK Navigator uyumlu layer JSON
GET /api/v1/mitre/activity  → Son 24h/7d taktik bazlı alert aktivitesi
"""

from fastapi import APIRouter, Depends
from server.auth import User, get_current_user
from server.correlator import correlator
from server.database import db
from server.mitre import get_coverage, get_heatmap, parse_mitre_tags

router = APIRouter()


@router.get("/mitre/coverage")
def mitre_coverage(_: User = Depends(get_current_user)):
    """
    Aktif korelasyon kurallarının MITRE ATT&CK kapsama haritası.
    Her taktik için kaç kural var, hangi teknikler kapsanıyor.
    """
    rules = correlator._rules
    return get_coverage(rules)


@router.get("/mitre/heatmap")
def mitre_heatmap(days: int = 30, _: User = Depends(get_current_user)):
    """
    ATT&CK Navigator uyumlu layer JSON.
    navigator.attack.mitre.org adresine import edilebilir.
    Son `days` günde kaç kez tetiklendiğini gösterir.
    """
    if days < 1 or days > 365:
        days = 30

    rules = correlator._rules

    # Son N gündeki kural bazlı alert sayıları
    with db._connect() as conn:
        rows = conn.execute(
            """
            SELECT rule_id, COUNT(*) as cnt
            FROM correlated_events
            WHERE created_at >= datetime('now', ?)
            GROUP BY rule_id
            """,
            (f"-{days} days",),
        ).fetchall()
    recent_alerts = [{"rule_id": r["rule_id"], "count": r["cnt"]} for r in rows]

    return get_heatmap(rules, recent_alerts)


@router.get("/mitre/techniques")
def list_techniques(_: User = Depends(get_current_user)):
    """
    Kural bazlı MITRE teknik listesi.
    Her kural için hangi teknikleri karşıladığını döner.
    """
    result = []
    for rule in correlator._rules:
        tags = getattr(rule, "tags", None) or []
        parsed = parse_mitre_tags(tags)
        if parsed["mitre_techniques"] or parsed["mitre_tactics"]:
            result.append({
                "rule_id":          rule.rule_id,
                "rule_name":        rule.name,
                "severity":         rule.severity,
                "mitre_techniques": parsed["mitre_techniques"],
                "mitre_tactics":    parsed["mitre_tactics"],
            })
    return {"count": len(result), "rules": result}


@router.get("/mitre/activity")
def mitre_activity(_: User = Depends(get_current_user)):
    """
    Son 24h ve 7d içinde her MITRE taktiğine ait korelasyon olayı sayısı.
    Taktik → {count_24h, count_7d} formatında döner.
    """
    rule_tactic_map: dict[str, list[str]] = {}
    for rule in correlator._rules:
        tags = getattr(rule, "tags", None) or []
        parsed = parse_mitre_tags(tags)
        if parsed["mitre_tactics"]:
            rule_tactic_map[rule.rule_id] = parsed["mitre_tactics"]

    with db._connect() as conn:
        rows_24h = conn.execute(
            """
            SELECT rule_id, COUNT(*) as cnt
            FROM correlated_events
            WHERE created_at >= datetime('now', '-1 day')
            GROUP BY rule_id
            """,
        ).fetchall()
        rows_7d = conn.execute(
            """
            SELECT rule_id, COUNT(*) as cnt
            FROM correlated_events
            WHERE created_at >= datetime('now', '-7 days')
            GROUP BY rule_id
            """,
        ).fetchall()

    counts_24h = {r["rule_id"]: r["cnt"] for r in rows_24h}
    counts_7d  = {r["rule_id"]: r["cnt"] for r in rows_7d}

    tactic_activity: dict[str, dict] = {}
    for rule_id, tactics in rule_tactic_map.items():
        for tactic in tactics:
            if tactic not in tactic_activity:
                tactic_activity[tactic] = {"count_24h": 0, "count_7d": 0}
            tactic_activity[tactic]["count_24h"] += counts_24h.get(rule_id, 0)
            tactic_activity[tactic]["count_7d"]  += counts_7d.get(rule_id, 0)

    return {"tactics": tactic_activity}
