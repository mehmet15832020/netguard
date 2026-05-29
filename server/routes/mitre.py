"""
NetGuard Server — MITRE ATT&CK Endpoints

GET /api/v1/mitre/coverage  → Hangi kurallar hangi tekniği/taktiği karşılıyor
GET /api/v1/mitre/heatmap   → ATT&CK Navigator uyumlu layer JSON
GET /api/v1/mitre/activity  → Son 24h/7d taktik bazlı alert aktivitesi
"""

from datetime import datetime, timedelta, timezone

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

    cutoff_n = datetime.now(timezone.utc) - timedelta(days=days)
    recent_alerts = [
        {"rule_id": r["rule_id"], "count": r["cnt"]}
        for r in db.get_rule_alert_counts(cutoff_n)
    ]

    return get_heatmap(rules, recent_alerts)


@router.get("/mitre/techniques")
def list_techniques(_: User = Depends(get_current_user)):
    """
    Kural bazlı MITRE teknik listesi.
    JSON korelasyon kuralları + pySigma V2 kurallarının tekniklerini döner.
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
    for v2_rule in correlator._sigma_executor.rules:
        tags = getattr(v2_rule, "tags", None) or []
        parsed = parse_mitre_tags(tags)
        if parsed["mitre_techniques"] or parsed["mitre_tactics"]:
            result.append({
                "rule_id":          v2_rule.rule_id,
                "rule_name":        v2_rule.title,
                "severity":         v2_rule.severity,
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

    now = datetime.now(timezone.utc)
    counts_24h = {r["rule_id"]: r["cnt"] for r in db.get_rule_alert_counts(now - timedelta(days=1))}
    counts_7d  = {r["rule_id"]: r["cnt"] for r in db.get_rule_alert_counts(now - timedelta(days=7))}

    tactic_activity: dict[str, dict] = {}
    for rule_id, tactics in rule_tactic_map.items():
        for tactic in tactics:
            if tactic not in tactic_activity:
                tactic_activity[tactic] = {"count_24h": 0, "count_7d": 0}
            tactic_activity[tactic]["count_24h"] += counts_24h.get(rule_id, 0)
            tactic_activity[tactic]["count_7d"]  += counts_7d.get(rule_id, 0)

    return {"tactics": tactic_activity}
