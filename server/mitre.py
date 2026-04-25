"""
NetGuard — MITRE ATT&CK Entegrasyonu

Sigma kural tags'lerinden teknik/taktik çıkarır.
Coverage (hangi teknikler kapsanıyor) ve ATT&CK Navigator uyumlu
heatmap verisi üretir.

Kullanım:
  parse_mitre_tags(["attack.t1110.001", "attack.credential_access"])
  → {"mitre_techniques": ["T1110.001"], "mitre_tactics": ["credential_access"]}
"""

import re
from typing import Optional

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


def _score_to_color(score: int) -> str:
    if score == 0:
        return "#c8c8c8"
    if score < 5:
        return "#ff9999"
    if score < 20:
        return "#ff6666"
    return "#ff0000"
