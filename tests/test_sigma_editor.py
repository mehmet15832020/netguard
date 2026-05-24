"""
R3 — Sigma YAML Editör backend testleri.

Editör, mevcut R2 endpoint'lerini kullanır:
  GET    /sigma/rules/{rule_id}    → YAML içeriğini yükle
  POST   /sigma/rules/validate     → pySigma doğrulama
  POST   /sigma/rules              → kaydet (aynı UUID → üzerine yaz)

Bu testler GET-by-ID, üzerine yazma ve editöre özel senaryo akışlarını kapsar.
"""

import textwrap
import pytest
from fastapi.testclient import TestClient
from server.main import app
import server.routes.sigma as sigma_mod

client = TestClient(app)

BASE_YAML = textwrap.dedent("""\
    title: Editor Test Base
    name: ng_editor_test_base
    status: test
    logsource:
        category: authentication
    detection:
        selection:
            event_action: login_failure
        condition: selection
    level: low
    ---
    title: Editor Test Correlation
    id: ed000001-aaaa-4bbb-8ccc-dddddddddddd
    correlation:
        type: event_count
        rules: ng_editor_test_base
        group-by:
            - source_ip
        timespan: 5m
        condition:
            gte: 5
    level: medium
    tags:
        - attack.credential_access
    falsepositives:
        - Automated tests
""")

UPDATED_YAML = textwrap.dedent("""\
    title: Editor Test Base
    name: ng_editor_test_base
    status: stable
    logsource:
        category: authentication
    detection:
        selection:
            event_action: login_failure
        condition: selection
    level: low
    ---
    title: Editor Test Correlation Updated
    id: ed000001-aaaa-4bbb-8ccc-dddddddddddd
    correlation:
        type: event_count
        rules: ng_editor_test_base
        group-by:
            - source_ip
        timespan: 10m
        condition:
            gte: 10
    level: high
    tags:
        - attack.credential_access
        - attack.t1110
    falsepositives:
        - Automated tests
        - Admin scripts
""")

SECOND_YAML = textwrap.dedent("""\
    title: DNS Exfil Base
    name: ng_dns_exfil_ed_base
    status: test
    logsource:
        category: dns
    detection:
        selection:
            event_action: dns_tunneling
        condition: selection
    level: medium
    ---
    title: DNS Exfil Correlation
    id: ed000002-aaaa-4bbb-8ccc-dddddddddddd
    correlation:
        type: event_count
        rules: ng_dns_exfil_ed_base
        group-by:
            - source_ip
        timespan: 10m
        condition:
            gte: 3
    level: high
    tags:
        - attack.command_and_control
        - attack.t1071.004
""")


@pytest.fixture()
def sigma_dir(tmp_path, monkeypatch):
    d = tmp_path / "sigma_rules_v2"
    d.mkdir()
    (d / "ed000001-aaaa-4bbb-8ccc-dddddddddddd.yml").write_text(BASE_YAML)
    monkeypatch.setattr(sigma_mod, "SIGMA_DIR", d)
    return d


# ─── GET /sigma/rules/{rule_id} ───────────────────────────────────────────────

class TestGetRule:
    def test_get_existing_rule_returns_yaml(self, sigma_dir, admin_token):
        r = client.get(
            "/api/v1/sigma/rules/ed000001-aaaa-4bbb-8ccc-dddddddddddd",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["rule_id"] == "ed000001-aaaa-4bbb-8ccc-dddddddddddd"
        assert "yaml_content" in data
        assert "Editor Test Correlation" in data["yaml_content"]

    def test_get_rule_filename_in_response(self, sigma_dir, admin_token):
        r = client.get(
            "/api/v1/sigma/rules/ed000001-aaaa-4bbb-8ccc-dddddddddddd",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.json()["filename"].endswith(".yml")

    def test_get_nonexistent_rule_returns_404(self, sigma_dir, admin_token):
        r = client.get(
            "/api/v1/sigma/rules/nonexistent-uuid-xyz",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 404

    def test_get_disabled_rule_by_id(self, sigma_dir, admin_token):
        yml_path = sigma_dir / "ed000001-aaaa-4bbb-8ccc-dddddddddddd.yml"
        yml_path.rename(sigma_dir / "ed000001-aaaa-4bbb-8ccc-dddddddddddd.yml.disabled")
        r = client.get(
            "/api/v1/sigma/rules/ed000001-aaaa-4bbb-8ccc-dddddddddddd",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert "yaml_content" in r.json()

    def test_get_rule_requires_auth(self, sigma_dir):
        r = client.get("/api/v1/sigma/rules/ed000001-aaaa-4bbb-8ccc-dddddddddddd")
        assert r.status_code == 401

    def test_get_rule_yaml_content_intact(self, sigma_dir, admin_token):
        original = (sigma_dir / "ed000001-aaaa-4bbb-8ccc-dddddddddddd.yml").read_text()
        r = client.get(
            "/api/v1/sigma/rules/ed000001-aaaa-4bbb-8ccc-dddddddddddd",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.json()["yaml_content"] == original


# ─── Overwrite (aynı UUID ile POST) ──────────────────────────────────────────

class TestEditorOverwrite:
    def test_overwrite_existing_rule(self, sigma_dir, admin_token):
        r = client.post(
            "/api/v1/sigma/rules",
            json={"yaml_content": UPDATED_YAML},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["saved"] == "ed000001-aaaa-4bbb-8ccc-dddddddddddd"

    def test_overwrite_updates_file_content(self, sigma_dir, admin_token):
        client.post(
            "/api/v1/sigma/rules",
            json={"yaml_content": UPDATED_YAML},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        content = (sigma_dir / "ed000001-aaaa-4bbb-8ccc-dddddddddddd.yml").read_text()
        assert "Editor Test Correlation Updated" in content
        assert "timespan: 10m" in content

    def test_overwrite_then_get_returns_updated(self, sigma_dir, admin_token):
        client.post(
            "/api/v1/sigma/rules",
            json={"yaml_content": UPDATED_YAML},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        r = client.get(
            "/api/v1/sigma/rules/ed000001-aaaa-4bbb-8ccc-dddddddddddd",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert "Editor Test Correlation Updated" in r.json()["yaml_content"]

    def test_overwrite_level_changes_in_list(self, sigma_dir, admin_token):
        client.post(
            "/api/v1/sigma/rules",
            json={"yaml_content": UPDATED_YAML},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        r = client.get(
            "/api/v1/sigma/rules",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        rule = next(
            (ru for ru in r.json()["rules"]
             if ru["rule_id"] == "ed000001-aaaa-4bbb-8ccc-dddddddddddd"),
            None,
        )
        assert rule is not None
        assert rule["level"] == "high"

    def test_file_count_unchanged_after_overwrite(self, sigma_dir, admin_token):
        files_before = len(list(sigma_dir.glob("*.yml")))
        client.post(
            "/api/v1/sigma/rules",
            json={"yaml_content": UPDATED_YAML},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        files_after = len(list(sigma_dir.glob("*.yml")))
        assert files_after == files_before


# ─── Validate → Save akışı (editör kullanım senaryosu) ───────────────────────

class TestEditorFlow:
    def test_validate_then_save_flow(self, sigma_dir, admin_token):
        headers = {"Authorization": f"Bearer {admin_token}"}
        # Adım 1: Doğrula
        val = client.post(
            "/api/v1/sigma/rules/validate",
            json={"yaml_content": SECOND_YAML},
            headers=headers,
        )
        assert val.status_code == 200
        assert val.json()["valid"] is True
        # Adım 2: Kaydet
        save = client.post(
            "/api/v1/sigma/rules",
            json={"yaml_content": SECOND_YAML},
            headers=headers,
        )
        assert save.status_code == 200
        assert save.json()["saved"] == "ed000002-aaaa-4bbb-8ccc-dddddddddddd"

    def test_validate_after_edit_detects_change(self, sigma_dir, admin_token):
        headers = {"Authorization": f"Bearer {admin_token}"}
        val = client.post(
            "/api/v1/sigma/rules/validate",
            json={"yaml_content": UPDATED_YAML},
            headers=headers,
        )
        assert val.json()["title"] == "Editor Test Correlation Updated"
        assert val.json()["level"] == "high"

    def test_invalid_yaml_blocks_save(self, sigma_dir, admin_token):
        headers = {"Authorization": f"Bearer {admin_token}"}
        bad_yaml = "title: [broken yaml"
        val = client.post(
            "/api/v1/sigma/rules/validate",
            json={"yaml_content": bad_yaml},
            headers=headers,
        )
        assert val.status_code == 422
        save = client.post(
            "/api/v1/sigma/rules",
            json={"yaml_content": bad_yaml},
            headers=headers,
        )
        assert save.status_code == 422

    def test_saved_rule_appears_in_list(self, sigma_dir, admin_token):
        headers = {"Authorization": f"Bearer {admin_token}"}
        client.post("/api/v1/sigma/rules", json={"yaml_content": SECOND_YAML}, headers=headers)
        r = client.get("/api/v1/sigma/rules", headers=headers)
        titles = [ru["title"] for ru in r.json()["rules"]]
        assert "DNS Exfil Correlation" in titles

    def test_tags_preserved_after_overwrite(self, sigma_dir, admin_token):
        headers = {"Authorization": f"Bearer {admin_token}"}
        client.post(
            "/api/v1/sigma/rules",
            json={"yaml_content": UPDATED_YAML},
            headers=headers,
        )
        r = client.get(
            "/api/v1/sigma/rules/ed000001-aaaa-4bbb-8ccc-dddddddddddd",
            headers=headers,
        )
        assert "attack.t1110" in r.json()["yaml_content"]
