"""MITRE ATT&CK entegrasyonu testleri."""

import pytest
from fastapi.testclient import TestClient
from server.main import app
from server.auth import create_access_token
from server.mitre import parse_mitre_tags, get_coverage, get_heatmap, TACTIC_META

client = TestClient(app)


def _auth():
    token = create_access_token(username="admin", role="admin")
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------ #
#  parse_mitre_tags
# ------------------------------------------------------------------ #

class TestParseMitreTags:
    def test_extracts_technique(self):
        result = parse_mitre_tags(["attack.t1110.001"])
        assert result["mitre_techniques"] == ["T1110.001"]
        assert result["mitre_tactics"] == []

    def test_extracts_tactic(self):
        result = parse_mitre_tags(["attack.credential_access"])
        assert result["mitre_tactics"] == ["credential_access"]
        assert result["mitre_techniques"] == []

    def test_extracts_both(self):
        tags = ["attack.credential_access", "attack.t1110.001", "attack.lateral_movement"]
        result = parse_mitre_tags(tags)
        assert "T1110.001" in result["mitre_techniques"]
        assert "credential_access" in result["mitre_tactics"]
        assert "lateral_movement" in result["mitre_tactics"]

    def test_ignores_non_attack_tags(self):
        result = parse_mitre_tags(["network.snmp", "impact.availability", "attack.t1046"])
        assert result["mitre_techniques"] == ["T1046"]
        assert result["mitre_tactics"] == []

    def test_deduplicates(self):
        result = parse_mitre_tags(["attack.t1110", "attack.t1110", "attack.credential_access", "attack.credential_access"])
        assert len(result["mitre_techniques"]) == 1
        assert len(result["mitre_tactics"]) == 1

    def test_hyphenated_tactic_normalized(self):
        result = parse_mitre_tags(["attack.lateral-movement"])
        assert "lateral_movement" in result["mitre_tactics"]

    def test_empty_tags(self):
        result = parse_mitre_tags([])
        assert result == {"mitre_techniques": [], "mitre_tactics": []}

    def test_technique_without_subtechnique(self):
        result = parse_mitre_tags(["attack.t1046"])
        assert "T1046" in result["mitre_techniques"]

    def test_uppercase_technique_normalized(self):
        result = parse_mitre_tags(["attack.T1110.001"])
        assert "T1110.001" in result["mitre_techniques"]


# ------------------------------------------------------------------ #
#  get_coverage
# ------------------------------------------------------------------ #

class TestGetCoverage:
    def _make_rule(self, rule_id: str, tags: list[str]):
        from dataclasses import dataclass
        @dataclass
        class FakeRule:
            rule_id: str
            tags: list

        return FakeRule(rule_id=rule_id, tags=tags)

    def test_single_rule_coverage(self):
        rule = self._make_rule("ssh_brute", ["attack.credential_access", "attack.t1110.001"])
        cov = get_coverage([rule])
        assert "credential_access" in cov["tactics"]
        assert "T1110.001" in cov["techniques"]
        assert cov["total_techniques"] == 1
        assert cov["total_rules_with_mitre"] == 1

    def test_multiple_rules_aggregate(self):
        rules = [
            self._make_rule("r1", ["attack.credential_access", "attack.t1110.001"]),
            self._make_rule("r2", ["attack.lateral_movement", "attack.t1021.001"]),
        ]
        cov = get_coverage(rules)
        assert "credential_access" in cov["tactics"]
        assert "lateral_movement" in cov["tactics"]
        assert cov["total_techniques"] == 2

    def test_rule_without_mitre_not_counted(self):
        rules = [
            self._make_rule("r1", ["attack.t1110"]),
            self._make_rule("r2", ["network.snmp"]),  # MITRE değil
        ]
        cov = get_coverage(rules)
        assert cov["total_rules_with_mitre"] == 1

    def test_empty_rules(self):
        cov = get_coverage([])
        assert cov["total_techniques"] == 0
        assert cov["tactics"] == {}


# ------------------------------------------------------------------ #
#  get_heatmap
# ------------------------------------------------------------------ #

class TestGetHeatmap:
    def _make_rule(self, rule_id: str, tags: list[str]):
        from dataclasses import dataclass
        @dataclass
        class FakeRule:
            rule_id: str
            tags: list
        return FakeRule(rule_id=rule_id, tags=tags)

    def test_heatmap_structure(self):
        rules = [self._make_rule("r1", ["attack.t1110.001"])]
        heatmap = get_heatmap(rules, [{"rule_id": "r1", "count": 5}])
        assert "name" in heatmap
        assert "techniques" in heatmap
        assert heatmap["domain"] == "enterprise-attack"

    def test_score_reflects_alert_count(self):
        rules = [self._make_rule("r1", ["attack.t1110.001"])]
        heatmap = get_heatmap(rules, [{"rule_id": "r1", "count": 10}])
        tech = next((t for t in heatmap["techniques"] if t["techniqueID"] == "T1110.001"), None)
        assert tech is not None
        assert tech["score"] == 10

    def test_uncovered_technique_gets_zero_score(self):
        rules = [self._make_rule("r1", ["attack.t1110.001"])]
        heatmap = get_heatmap(rules, [])  # sıfır alert
        tech = next((t for t in heatmap["techniques"] if t["techniqueID"] == "T1110.001"), None)
        assert tech is not None
        assert tech["score"] == 0

    def test_navigator_version_fields(self):
        heatmap = get_heatmap([], [])
        assert "versions" in heatmap
        assert "navigator" in heatmap["versions"]


# ------------------------------------------------------------------ #
#  API endpoint'leri
# ------------------------------------------------------------------ #

class TestMitreEndpoints:
    def test_coverage_requires_auth(self, tmp_db):
        r = client.get("/api/v1/mitre/coverage")
        assert r.status_code == 401

    def test_coverage_returns_200(self, tmp_db):
        r = client.get("/api/v1/mitre/coverage", headers=_auth())
        assert r.status_code == 200
        data = r.json()
        assert "tactics" in data
        assert "total_techniques" in data

    def test_heatmap_returns_200(self, tmp_db):
        r = client.get("/api/v1/mitre/heatmap", headers=_auth())
        assert r.status_code == 200
        data = r.json()
        assert "techniques" in data
        assert "domain" in data

    def test_techniques_returns_200(self, tmp_db):
        r = client.get("/api/v1/mitre/techniques", headers=_auth())
        assert r.status_code == 200
        data = r.json()
        assert "rules" in data
        assert "count" in data

    def test_heatmap_invalid_days_clamped(self, tmp_db):
        r = client.get("/api/v1/mitre/heatmap?days=999", headers=_auth())
        assert r.status_code == 200  # 999 → 30'a düşürülür

    def test_real_sigma_rules_have_mitre_tags(self, tmp_db):
        r = client.get("/api/v1/mitre/techniques", headers=_auth())
        data = r.json()
        # En az 5 Windows + Linux kuralı MITRE etiketli olmalı
        assert data["count"] >= 5
