"""
NetGuard — MITRE ATT&CK Entegrasyonu

Sigma kural tags'lerinden teknik/taktik çıkarır.
Coverage (hangi teknikler kapsanıyor) ve ATT&CK Navigator uyumlu
heatmap verisi üretir.

Kullanım:
  parse_mitre_tags(["attack.t1110.001", "attack.credential_access"])
  → {"mitre_techniques": ["T1110.001"], "mitre_tactics": ["credential_access"]}
"""

import json
import re
from pathlib import Path
from typing import Optional

_TECHNIQUE_DB_PATH = Path(__file__).parent.parent / "config" / "mitre_techniques.json"
_technique_db: dict | None = None


def load_technique_db() -> dict:
    """config/mitre_techniques.json'ı yükler (process başına bir kez)."""
    global _technique_db
    if _technique_db is None:
        _technique_db = json.loads(_TECHNIQUE_DB_PATH.read_text(encoding="utf-8"))
    return _technique_db

# MITRE ATT&CK taktik slug → okunabilir ad + Navigator ID
TACTIC_META: dict[str, dict] = {
    "reconnaissance":        {"label": "Reconnaissance",        "id": "TA0043"},
    "resource_development":  {"label": "Resource Development",  "id": "TA0042"},
    "initial_access":        {"label": "Initial Access",        "id": "TA0001"},
    "execution":             {"label": "Execution",             "id": "TA0002"},
    "persistence":           {"label": "Persistence",           "id": "TA0003"},
    "privilege_escalation":  {"label": "Privilege Escalation",  "id": "TA0004"},
    "defense_evasion":       {"label": "Defense Evasion",       "id": "TA0005"},
    "credential_access":     {"label": "Credential Access",     "id": "TA0006"},
    "discovery":             {"label": "Discovery",             "id": "TA0007"},
    "lateral_movement":      {"label": "Lateral Movement",      "id": "TA0008"},
    "collection":            {"label": "Collection",            "id": "TA0009"},
    "command_and_control":   {"label": "Command and Control",   "id": "TA0011"},
    "exfiltration":          {"label": "Exfiltration",          "id": "TA0010"},
    "impact":                {"label": "Impact",                "id": "TA0040"},
}

# Taktik adlarının "attack.X" tag formatındaki karşılıkları
_TACTIC_ALIASES = {
    "credential-access":     "credential_access",
    "lateral-movement":      "lateral_movement",
    "privilege-escalation":  "privilege_escalation",
    "defense-evasion":       "defense_evasion",
    "command-and-control":   "command_and_control",
    "initial-access":        "initial_access",
    "resource-development":  "resource_development",
}

_TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$", re.IGNORECASE)


def parse_mitre_tags(tags: list[str]) -> dict:
    """
    Sigma tags listesinden MITRE teknik ve taktikleri ayıklar.

    Giriş örneği:
      ["attack.credential_access", "attack.t1110.001", "attack.lateral_movement"]

    Çıkış:
      {
        "mitre_techniques": ["T1110.001"],
        "mitre_tactics":    ["credential_access", "lateral_movement"]
      }
    """
    techniques: list[str] = []
    tactics: list[str]    = []

    for tag in tags:
        tag = tag.strip().lower()
        if not tag.startswith("attack."):
            continue
        value = tag[len("attack."):]

        # Teknik mi? (T1234 veya T1234.001)
        if _TECHNIQUE_RE.match(value):
            techniques.append(value.upper())
            continue

        # Taktik mi?
        normalized = _TACTIC_ALIASES.get(value, value.replace("-", "_"))
        if normalized in TACTIC_META:
            tactics.append(normalized)

    return {
        "mitre_techniques": sorted(set(techniques)),
        "mitre_tactics":    sorted(set(tactics)),
    }


def get_coverage(rules: list) -> dict:
    """
    CorrelationRule listesinden MITRE kapsama haritası üretir.

    Dönüş:
      {
        "tactics": {
          "credential_access": {
            "label": "Credential Access",
            "tactic_id": "TA0006",
            "techniques": ["T1110", "T1110.001"],
            "rule_count": 3
          }
        },
        "techniques": {"T1110.001": ["ssh_brute_force", "windows_brute_force"]},
        "total_rules_with_mitre": 8,
        "total_techniques": 12,
      }
    """
    tactics_map: dict[str, dict] = {}
    technique_to_rules: dict[str, list[str]] = {}

    for rule in rules:
        tags = getattr(rule, "tags", None) or []
        parsed = parse_mitre_tags(tags)

        for tactic in parsed["mitre_tactics"]:
            if tactic not in tactics_map:
                meta = TACTIC_META.get(tactic, {"label": tactic.replace("_", " ").title(), "id": "?"})
                tactics_map[tactic] = {
                    "label":      meta["label"],
                    "tactic_id":  meta["id"],
                    "techniques": [],
                    "rule_count": 0,
                }
            tactics_map[tactic]["rule_count"] += 1

        for tech in parsed["mitre_techniques"]:
            if tech not in technique_to_rules:
                technique_to_rules[tech] = []
            technique_to_rules[tech].append(rule.rule_id)

            # Tekniği taktiklerle ilişkilendir
            for tactic in parsed["mitre_tactics"]:
                if tactic in tactics_map and tech not in tactics_map[tactic]["techniques"]:
                    tactics_map[tactic]["techniques"].append(tech)

    rules_with_mitre = sum(
        1 for r in rules
        if any(t.startswith("attack.") for t in (getattr(r, "tags", None) or []))
    )

    return {
        "tactics":                tactics_map,
        "techniques":             technique_to_rules,
        "total_rules_with_mitre": rules_with_mitre,
        "total_techniques":       len(technique_to_rules),
    }


def get_heatmap(rules: list, recent_alerts: list[dict]) -> dict:
    """
    ATT&CK Navigator uyumlu heatmap JSON üretir.
    recent_alerts: [{"rule_id": ..., "count": ...}, ...]

    Dönüş formatı ATT&CK Navigator layer v4.5 ile uyumludur.
    navigator.attack.mitre.org adresine yüklenebilir.
    """
    alert_counts: dict[str, int] = {a["rule_id"]: a["count"] for a in recent_alerts}
    rule_tags: dict[str, list[str]] = {
        r.rule_id: (getattr(r, "tags", None) or []) for r in rules
    }

    tech_scores: dict[str, int] = {}
    for rule_id, tags in rule_tags.items():
        parsed = parse_mitre_tags(tags)
        score = alert_counts.get(rule_id, 0)
        for tech in parsed["mitre_techniques"]:
            tech_scores[tech] = tech_scores.get(tech, 0) + score

    techniques = []
    for tech_id, score in tech_scores.items():
        # T1110.001 → T1110, .001
        parts = tech_id.split(".")
        entry: dict = {
            "techniqueID": tech_id,
            "score":       score,
            "color":       _score_to_color(score),
        }
        if len(parts) == 2:
            entry["subtechnique"] = True
        techniques.append(entry)

    # Skoru olmayan ama kapsanan teknikler de gri olarak eklenir
    for rule_id, tags in rule_tags.items():
        parsed = parse_mitre_tags(tags)
        for tech in parsed["mitre_techniques"]:
            if not any(t["techniqueID"] == tech for t in techniques):
                techniques.append({
                    "techniqueID": tech,
                    "score":       0,
                    "color":       "#c8c8c8",
                })

    return {
        "name":        "NetGuard Coverage",
        "versions":    {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain":      "enterprise-attack",
        "description": "NetGuard tarafından otomatik üretilmiştir.",
        "techniques":  techniques,
        "gradient":    {
            "colors": ["#c8c8c8", "#ff6666", "#ff0000"],
            "minValue": 0,
            "maxValue": max((t["score"] for t in techniques), default=1),
        },
    }


def get_matrix(rules: list, recent_alerts: list[dict]) -> dict:
    """
    MITRE ATT&CK matrisini coverage + aktivite verisiyle zenginleştirir.

    rules: correlator._rules + _sigma_executor.rules
    recent_alerts: [{"rule_id": ..., "count": ...}]

    Dönüş: taktik listesi (technique kartları + coverage özeti + top gap'ler)
    """
    db = load_technique_db()

    # Hangi teknikler hangi kurallar tarafından kapsanıyor
    tech_to_rules: dict[str, list[str]] = {}
    for rule in rules:
        tags = getattr(rule, "tags", None) or []
        parsed = parse_mitre_tags(tags)
        rule_name = getattr(rule, "name", None) or getattr(rule, "title", str(getattr(rule, "rule_id", "")))
        for tech in parsed["mitre_techniques"]:
            tech_to_rules.setdefault(tech, [])
            if rule_name not in tech_to_rules[tech]:
                tech_to_rules[tech].append(rule_name)
            # Üst tekniği de say (T1110.001 → T1110)
            parent = tech.split(".")[0]
            if parent != tech:
                tech_to_rules.setdefault(parent, [])
                if rule_name not in tech_to_rules[parent]:
                    tech_to_rules[parent].append(rule_name)

    # Kural bazlı alert sayıları
    alert_counts: dict[str, int] = {a["rule_id"]: a["count"] for a in recent_alerts}

    # Teknik bazlı 30 günlük hit sayısı
    tech_hits: dict[str, int] = {}
    for rule in rules:
        tags = getattr(rule, "tags", None) or []
        parsed = parse_mitre_tags(tags)
        hits = alert_counts.get(str(getattr(rule, "rule_id", "")), 0)
        for tech in parsed["mitre_techniques"]:
            tech_hits[tech] = tech_hits.get(tech, 0) + hits
            parent = tech.split(".")[0]
            if parent != tech:
                tech_hits[parent] = tech_hits.get(parent, 0) + hits

    total_techniques = 0
    covered_techniques = 0
    top_gaps: list[dict] = []

    tactic_results = []
    for tactic in db["tactics"]:
        tactic_slug  = tactic["slug"]
        tactic_label = tactic["label"]
        tactic_id    = tactic["id"]

        tactic_total   = 0
        tactic_covered = 0
        technique_rows = []

        for tech in tactic["techniques"]:
            tid   = tech["id"]
            tname = tech["name"]
            covered = tid in tech_to_rules

            sub_rows = []
            for sub in tech.get("subtechniques", []):
                sid   = sub["id"]
                sname = sub["name"]
                s_covered = sid in tech_to_rules
                sub_rows.append({
                    "id":       sid,
                    "name":     sname,
                    "covered":  s_covered,
                    "rules":    tech_to_rules.get(sid, []),
                    "hits_30d": tech_hits.get(sid, 0),
                })
                total_techniques += 1
                if s_covered:
                    covered_techniques += 1
                    tactic_covered += 1
                else:
                    top_gaps.append({"id": sid, "name": sname, "tactic_slug": tactic_slug, "tactic_label": tactic_label})
                tactic_total += 1

            technique_rows.append({
                "id":             tid,
                "name":           tname,
                "covered":        covered,
                "rules":          tech_to_rules.get(tid, []),
                "hits_30d":       tech_hits.get(tid, 0),
                "subtechniques":  sub_rows,
            })
            total_techniques += 1
            tactic_total += 1
            if covered:
                covered_techniques += 1
                tactic_covered += 1
            else:
                top_gaps.append({"id": tid, "name": tname, "tactic_slug": tactic_slug, "tactic_label": tactic_label})

        coverage_pct = round(tactic_covered / tactic_total * 100, 1) if tactic_total else 0.0
        tactic_results.append({
            "id":           tactic_id,
            "slug":         tactic_slug,
            "label":        tactic_label,
            "coverage_pct": coverage_pct,
            "covered":      tactic_covered,
            "total":        tactic_total,
            "techniques":   technique_rows,
        })

    overall_pct = round(covered_techniques / total_techniques * 100, 1) if total_techniques else 0.0

    # Top gap: kapsanmayan teknikler, yüksek riskli taktikler önce
    _HIGH_RISK = {"initial_access", "lateral_movement", "command_and_control", "credential_access", "exfiltration"}
    top_gaps.sort(key=lambda g: (0 if g["tactic_slug"] in _HIGH_RISK else 1, g["id"]))

    return {
        "tactics": tactic_results,
        "summary": {
            "total_techniques":   total_techniques,
            "covered_techniques": covered_techniques,
            "coverage_pct":       overall_pct,
            "top_gaps":           top_gaps[:15],
        },
    }


def _score_to_color(score: int) -> str:
    if score == 0:
        return "#c8c8c8"
    if score < 5:
        return "#ff9999"
    if score < 20:
        return "#ff6666"
    return "#ff0000"
