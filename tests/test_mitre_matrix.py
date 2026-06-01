"""
F3 — MITRE ATT&CK Matrix testleri.

GET /api/v1/mitre/matrix
server/mitre.py: get_matrix(), load_technique_db()
"""

import pytest
from types import SimpleNamespace
from fastapi.testclient import TestClient
from server.main import app
from server.mitre import get_matrix, load_technique_db

client = TestClient(app)


def _rule(rule_id: str, tags: list[str], name: str = "") -> SimpleNamespace:
    return SimpleNamespace(rule_id=rule_id, tags=tags, name=name or rule_id, title=name or rule_id, severity="high")


# ─── load_technique_db ────────────────────────────────────────────────────────

class TestLoadTechniqueDb:
    def test_returns_dict_with_tactics(self):
        db = load_technique_db()
        assert "tactics" in db
        assert len(db["tactics"]) == 13

    def test_each_tactic_has_required_keys(self):
        db = load_technique_db()
        for tactic in db["tactics"]:
            assert "id" in tactic
            assert "slug" in tactic
            assert "label" in tactic
            assert "techniques" in tactic

    def test_technique_db_cached(self):
        db1 = load_technique_db()
        db2 = load_technique_db()
        assert db1 is db2

    def test_all_technique_ids_start_with_T(self):
        db = load_technique_db()
        for tactic in db["tactics"]:
            for tech in tactic["techniques"]:
                assert tech["id"].startswith("T"), tech["id"]
                for sub in tech.get("subtechniques", []):
                    assert sub["id"].startswith("T"), sub["id"]


# ─── get_matrix ───────────────────────────────────────────────────────────────

class TestGetMatrix:
    def test_no_rules_returns_zero_coverage(self):
        result = get_matrix([], [])
        assert result["summary"]["covered_techniques"] == 0
        assert result["summary"]["coverage_pct"] == 0.0

    def test_covered_technique_marked_correctly(self):
        rules = [_rule("r1", ["attack.t1110.001", "attack.credential_access"])]
        result = get_matrix(rules, [])
        cred = next(t for t in result["tactics"] if t["slug"] == "credential_access")
        brute = next(t for t in cred["techniques"] if t["id"] == "T1110")
        sub = next(s for s in brute["subtechniques"] if s["id"] == "T1110.001")
        assert sub["covered"] is True
        assert "r1" in sub["rules"]

    def test_parent_technique_covered_when_subtechnique_covered(self):
        rules = [_rule("r1", ["attack.t1110.001", "attack.credential_access"])]
        result = get_matrix(rules, [])
        cred = next(t for t in result["tactics"] if t["slug"] == "credential_access")
        brute = next(t for t in cred["techniques"] if t["id"] == "T1110")
        assert brute["covered"] is True

    def test_uncovered_technique_in_top_gaps(self):
        result = get_matrix([], [])
        gaps = result["summary"]["top_gaps"]
        assert len(gaps) > 0
        gap_slugs = {g["tactic_slug"] for g in gaps}
        high_risk = {"initial_access", "lateral_movement", "command_and_control", "credential_access", "exfiltration"}
        assert gap_slugs & high_risk

    def test_hits_30d_populated_from_alerts(self):
        rules = [_rule("r1", ["attack.t1046", "attack.discovery"])]
        alerts = [{"rule_id": "r1", "count": 42}]
        result = get_matrix(rules, alerts)
        disc = next(t for t in result["tactics"] if t["slug"] == "discovery")
        nsd = next(t for t in disc["techniques"] if t["id"] == "T1046")
        assert nsd["hits_30d"] == 42

    def test_summary_total_techniques_nonzero(self):
        result = get_matrix([], [])
        assert result["summary"]["total_techniques"] > 50

    def test_top_gaps_prioritizes_high_risk_tactics(self):
        result = get_matrix([], [])
        gaps = result["summary"]["top_gaps"]
        high_risk = {"initial_access", "lateral_movement", "command_and_control", "credential_access", "exfiltration"}
        first_slugs = {g["tactic_slug"] for g in gaps[:5]}
        assert first_slugs & high_risk

    def test_coverage_pct_increases_with_more_rules(self):
        r0 = get_matrix([], [])
        rules = [
            _rule("r1", ["attack.t1046", "attack.discovery"]),
            _rule("r2", ["attack.t1110.001", "attack.credential_access"]),
        ]
        r2 = get_matrix(rules, [])
        assert r2["summary"]["coverage_pct"] > r0["summary"]["coverage_pct"]

    def test_tactics_list_has_13_entries(self):
        result = get_matrix([], [])
        assert len(result["tactics"]) == 13

    def test_tactic_coverage_pct_between_0_and_100(self):
        result = get_matrix([], [])
        for tactic in result["tactics"]:
            assert 0.0 <= tactic["coverage_pct"] <= 100.0


# ─── Route: GET /mitre/matrix ─────────────────────────────────────────────────

class TestMitreMatrixRoute:
    def test_requires_auth(self):
        r = client.get("/api/v1/mitre/matrix")
        assert r.status_code == 401

    def test_returns_200_with_auth(self, tmp_db, admin_token):
        r = client.get(
            "/api/v1/mitre/matrix",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

    def test_response_shape(self, tmp_db, admin_token):
        r = client.get(
            "/api/v1/mitre/matrix",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        data = r.json()
        assert "tactics" in data
        assert "summary" in data
        summary = data["summary"]
        assert "total_techniques" in summary
        assert "covered_techniques" in summary
        assert "coverage_pct" in summary
        assert "top_gaps" in summary

    def test_days_param_clamped(self, tmp_db, admin_token):
        r = client.get(
            "/api/v1/mitre/matrix?days=999",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

    def test_top_gaps_is_list(self, tmp_db, admin_token):
        r = client.get(
            "/api/v1/mitre/matrix",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert isinstance(r.json()["summary"]["top_gaps"], list)
