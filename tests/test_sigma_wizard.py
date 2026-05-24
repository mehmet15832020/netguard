"""
R2 — Sigma Rule Wizard backend testleri.

GET    /sigma/rules                    → liste (disabled dahil)
POST   /sigma/rules/validate           → pySigma doğrulama
POST   /sigma/rules                    → kaydet + hot-reload
DELETE /sigma/rules/{rule_id}          → sil
PATCH  /sigma/rules/{rule_id}/toggle   → aktif/pasif (.yml ↔ .yml.disabled)
"""

import textwrap
import pytest
from fastapi.testclient import TestClient
from server.main import app
import server.routes.sigma as sigma_mod

client = TestClient(app)

VALID_SIGMA_YAML = textwrap.dedent("""\
    title: SSH Failure Base
    name: ng_ssh_fail_wiz_base
    status: stable
    logsource:
        category: authentication
    detection:
        selection:
            event_action: ssh_failure
        condition: selection
    level: low
    ---
    title: SSH Brute Force (Wizard Test)
    id: aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
    correlation:
        type: event_count
        rules: ng_ssh_fail_wiz_base
        group-by:
            - source_ip
        timespan: 5m
        condition:
            gte: 5
    level: high
    tags:
        - attack.credential_access
        - attack.t1110
    falsepositives:
        - Normal admin SSH
""")

VALID_SIGMA_YAML_2 = textwrap.dedent("""\
    title: Port Scan Base
    name: ng_portscan_wiz_base
    status: test
    logsource:
        category: network
    detection:
        selection:
            event_action: port_scan
        condition: selection
    level: low
    ---
    title: Port Sweep (Wizard Test)
    id: 11111111-2222-4333-8444-555555555555
    correlation:
        type: event_count
        rules: ng_portscan_wiz_base
        group-by:
            - source_ip
        timespan: 1m
        condition:
            gte: 10
    level: medium
    tags:
        - attack.reconnaissance
        - attack.t1046
""")


@pytest.fixture()
def sigma_dir(tmp_path, monkeypatch):
    """Sigma kural dizinini geçici dizine yönlendir."""
    d = tmp_path / "sigma_rules_v2"
    d.mkdir()
    (d / "ssh_brute.yml").write_text(VALID_SIGMA_YAML)
    monkeypatch.setattr(sigma_mod, "SIGMA_DIR", d)
    return d


# ─── GET /sigma/rules ─────────────────────────────────────────────────────────

class TestSigmaList:
    def test_list_returns_enabled_rules(self, sigma_dir, admin_token):
        r = client.get("/api/v1/sigma/rules",
                       headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        data = r.json()
        assert data["count"] >= 1
        assert any(rule["enabled"] for rule in data["rules"])

    def test_list_includes_disabled_rules(self, sigma_dir, admin_token):
        (sigma_dir / "disabled_rule.yml.disabled").write_text(VALID_SIGMA_YAML_2)
        r = client.get("/api/v1/sigma/rules",
                       headers={"Authorization": f"Bearer {admin_token}"})
        rules = r.json()["rules"]
        assert any(not rule["enabled"] for rule in rules)

    def test_list_disabled_rule_has_enabled_false(self, sigma_dir, admin_token):
        (sigma_dir / "disabled_rule.yml.disabled").write_text(VALID_SIGMA_YAML_2)
        r = client.get("/api/v1/sigma/rules",
                       headers={"Authorization": f"Bearer {admin_token}"})
        disabled = [rule for rule in r.json()["rules"] if not rule["enabled"]]
        assert len(disabled) >= 1
        assert disabled[0]["title"] == "Port Sweep (Wizard Test)"

    def test_list_empty_dir_returns_zero(self, tmp_path, monkeypatch, admin_token):
        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.setattr(sigma_mod, "SIGMA_DIR", empty)
        r = client.get("/api/v1/sigma/rules",
                       headers={"Authorization": f"Bearer {admin_token}"})
        assert r.json()["count"] == 0

    def test_list_requires_auth(self, sigma_dir):
        r = client.get("/api/v1/sigma/rules")
        assert r.status_code == 401


# ─── POST /sigma/rules/validate ──────────────────────────────────────────────

class TestSigmaValidate:
    def test_validate_valid_yaml_returns_200(self, sigma_dir, admin_token):
        r = client.post("/api/v1/sigma/rules/validate",
                        json={"yaml_content": VALID_SIGMA_YAML},
                        headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is True
        assert data["title"] == "SSH Brute Force (Wizard Test)"
        assert data["is_correlation"] is True
        assert data["level"] == "high"

    def test_validate_invalid_yaml_returns_422(self, sigma_dir, admin_token):
        r = client.post("/api/v1/sigma/rules/validate",
                        json={"yaml_content": "not: [valid yaml"},
                        headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 422

    def test_validate_empty_yaml_returns_422(self, sigma_dir, admin_token):
        r = client.post("/api/v1/sigma/rules/validate",
                        json={"yaml_content": ""},
                        headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 422

    def test_validate_requires_auth(self, sigma_dir):
        r = client.post("/api/v1/sigma/rules/validate",
                        json={"yaml_content": VALID_SIGMA_YAML})
        assert r.status_code == 401

    def test_validate_startswith_modifier(self, sigma_dir, admin_token):
        yaml_startswith = textwrap.dedent("""\
            title: SSH All Base
            name: ng_ssh_all_sw_base
            status: test
            logsource:
                category: authentication
            detection:
                selection:
                    event_action|startswith: ssh_
                condition: selection
            level: low
            ---
            title: SSH Activity
            id: 22222222-3333-4444-8555-666666666666
            correlation:
                type: event_count
                rules: ng_ssh_all_sw_base
                group-by:
                    - source_ip
                timespan: 10m
                condition:
                    gte: 20
            level: medium
        """)
        r = client.post("/api/v1/sigma/rules/validate",
                        json={"yaml_content": yaml_startswith},
                        headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert r.json()["valid"] is True

    def test_validate_multi_field_detection(self, sigma_dir, admin_token):
        yaml_multi = textwrap.dedent("""\
            title: Auth Fail Base
            name: ng_auth_fail_multi_base
            status: test
            logsource:
                category: authentication
            detection:
                selection:
                    event_action: auth_failure
                    event_category: authentication
                condition: selection
            level: low
            ---
            title: Auth Brute Force
            id: 33333333-4444-4555-8666-777777777777
            correlation:
                type: event_count
                rules: ng_auth_fail_multi_base
                group-by:
                    - username
                timespan: 5m
                condition:
                    gte: 3
            level: high
        """)
        r = client.post("/api/v1/sigma/rules/validate",
                        json={"yaml_content": yaml_multi},
                        headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200


# ─── POST /sigma/rules ────────────────────────────────────────────────────────

class TestSigmaCreate:
    def test_create_valid_rule_saves_file(self, sigma_dir, admin_token):
        r = client.post("/api/v1/sigma/rules",
                        json={"yaml_content": VALID_SIGMA_YAML_2},
                        headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert r.json()["saved"] == "11111111-2222-4333-8444-555555555555"
        assert (sigma_dir / f"{r.json()['saved']}.yml").exists()

    def test_create_invalid_yaml_returns_422(self, sigma_dir, admin_token):
        r = client.post("/api/v1/sigma/rules",
                        json={"yaml_content": "bad: [yaml"},
                        headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 422

    def test_create_requires_admin(self, sigma_dir):
        r = client.post("/api/v1/sigma/rules",
                        json={"yaml_content": VALID_SIGMA_YAML_2})
        assert r.status_code == 401

    def test_create_rule_appears_in_list(self, sigma_dir, admin_token):
        client.post("/api/v1/sigma/rules",
                    json={"yaml_content": VALID_SIGMA_YAML_2},
                    headers={"Authorization": f"Bearer {admin_token}"})
        r = client.get("/api/v1/sigma/rules",
                       headers={"Authorization": f"Bearer {admin_token}"})
        titles = [rule["title"] for rule in r.json()["rules"]]
        assert "Port Sweep (Wizard Test)" in titles

    def test_create_rule_contains_tags(self, sigma_dir, admin_token):
        r = client.post("/api/v1/sigma/rules",
                        json={"yaml_content": VALID_SIGMA_YAML_2},
                        headers={"Authorization": f"Bearer {admin_token}"})
        rule_id = r.json()["saved"]
        r2 = client.get(f"/api/v1/sigma/rules/{rule_id}",
                        headers={"Authorization": f"Bearer {admin_token}"})
        assert "attack.t1046" in r2.json()["yaml_content"]


# ─── DELETE /sigma/rules/{rule_id} ────────────────────────────────────────────

class TestSigmaDelete:
    def test_delete_existing_rule(self, sigma_dir, admin_token):
        r = client.delete("/api/v1/sigma/rules/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                          headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert r.json()["deleted"] == "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

    def test_delete_removes_file(self, sigma_dir, admin_token):
        client.delete("/api/v1/sigma/rules/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                      headers={"Authorization": f"Bearer {admin_token}"})
        yml_files = list(sigma_dir.glob("*.yml"))
        assert not any("ssh_brute" in f.name for f in yml_files)

    def test_delete_missing_rule_returns_404(self, sigma_dir, admin_token):
        r = client.delete("/api/v1/sigma/rules/nonexistent-uuid",
                          headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 404

    def test_delete_disabled_rule(self, sigma_dir, admin_token):
        (sigma_dir / "disabled_rule.yml.disabled").write_text(VALID_SIGMA_YAML_2)
        r = client.delete("/api/v1/sigma/rules/11111111-2222-4333-8444-555555555555",
                          headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert not (sigma_dir / "disabled_rule.yml.disabled").exists()

    def test_delete_requires_admin(self, sigma_dir):
        r = client.delete("/api/v1/sigma/rules/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
        assert r.status_code == 401


# ─── PATCH /sigma/rules/{rule_id}/toggle ─────────────────────────────────────

class TestSigmaToggle:
    def test_toggle_enabled_to_disabled(self, sigma_dir, admin_token):
        r = client.patch("/api/v1/sigma/rules/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/toggle",
                         headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert r.json()["enabled"] is False
        assert r.json()["filename"].endswith(".yml.disabled")

    def test_toggle_renames_to_disabled(self, sigma_dir, admin_token):
        client.patch("/api/v1/sigma/rules/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/toggle",
                     headers={"Authorization": f"Bearer {admin_token}"})
        assert not (sigma_dir / "ssh_brute.yml").exists()
        assert (sigma_dir / "ssh_brute.yml.disabled").exists()

    def test_toggle_disabled_to_enabled(self, sigma_dir, admin_token):
        (sigma_dir / "ssh_brute.yml").rename(sigma_dir / "ssh_brute.yml.disabled")
        r = client.patch("/api/v1/sigma/rules/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/toggle",
                         headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert r.json()["enabled"] is True
        assert r.json()["filename"].endswith(".yml")

    def test_toggle_renames_back_to_yml(self, sigma_dir, admin_token):
        (sigma_dir / "ssh_brute.yml").rename(sigma_dir / "ssh_brute.yml.disabled")
        client.patch("/api/v1/sigma/rules/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/toggle",
                     headers={"Authorization": f"Bearer {admin_token}"})
        assert (sigma_dir / "ssh_brute.yml").exists()
        assert not (sigma_dir / "ssh_brute.yml.disabled").exists()

    def test_toggle_missing_rule_returns_404(self, sigma_dir, admin_token):
        r = client.patch("/api/v1/sigma/rules/nonexistent-id/toggle",
                         headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 404

    def test_toggle_requires_admin(self, sigma_dir):
        r = client.patch("/api/v1/sigma/rules/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/toggle")
        assert r.status_code == 401

    def test_toggle_disabled_rule_not_in_correlator_active(self, sigma_dir, admin_token):
        """Pasif edilen kural correlator'ın aktif listesine girmez."""
        client.patch("/api/v1/sigma/rules/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/toggle",
                     headers={"Authorization": f"Bearer {admin_token}"})
        from server.correlator import correlator as _corr
        sigma_titles = {r.title for r in _corr._sigma_executor.rules}
        assert "SSH Brute Force (Wizard Test)" not in sigma_titles
