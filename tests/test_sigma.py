"""
Tests for pySigma V2 rule parsing and NetGuard sigma route integration.
"""

import textwrap
from pathlib import Path

import pytest
import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

from server.sigma_executor import SigmaExecutor, SigmaExecutableRule


# ------------------------------------------------------------------ #
#  SigmaCollection parsing
# ------------------------------------------------------------------ #

VALID_V2_YAML = textwrap.dedent("""\
    title: SSH Failure Base
    name: ng_ssh_fail_test
    status: stable
    logsource:
        category: authentication
    detection:
        selection:
            event_action: ssh_failure
        condition: selection
    level: low
    ---
    title: SSH Brute Force Test
    id: 11111111-2222-3333-4444-555555555555
    correlation:
        type: event_count
        rules: ng_ssh_fail_test
        group-by:
            - source_ip
        timespan: 5m
        condition:
            gte: 5
    level: high
    tags:
        - attack.credential_access
        - attack.t1110
""")


def test_pysigma_parses_valid_multidoc_yaml():
    col = SigmaCollection.from_yaml(VALID_V2_YAML)
    rules = list(col)
    assert len(rules) == 2


def test_pysigma_last_rule_is_correlation():
    col = SigmaCollection.from_yaml(VALID_V2_YAML)
    rules = list(col)
    assert isinstance(rules[-1], SigmaCorrelationRule)


def test_pysigma_correlation_rule_fields():
    col = SigmaCollection.from_yaml(VALID_V2_YAML)
    rules = list(col)
    cr = rules[-1]
    assert str(cr.id) == "11111111-2222-3333-4444-555555555555"
    assert cr.title == "SSH Brute Force Test"
    assert cr.level.name == "HIGH"
    assert cr.timespan.seconds == 300


def test_pysigma_rejects_invalid_yaml():
    with pytest.raises(Exception):
        SigmaCollection.from_yaml("not: valid: yaml: [")


def test_pysigma_rejects_empty_yaml():
    col = SigmaCollection.from_yaml("")
    assert list(col) == []


def test_pysigma_tags_parsed():
    col = SigmaCollection.from_yaml(VALID_V2_YAML)
    rules = list(col)
    cr = rules[-1]
    tag_strings = [str(t) for t in cr.tags]
    assert "attack.credential_access" in tag_strings
    assert "attack.t1110" in tag_strings


# ------------------------------------------------------------------ #
#  SigmaExecutor — unit level
# ------------------------------------------------------------------ #

def test_executor_loads_v2_dir():
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    assert len(ex.rules) >= 10


def test_executor_all_rules_have_valid_severity():
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    valid = {"info", "warning", "high", "critical"}
    for r in ex.rules:
        assert r.severity in valid, f"{r.title!r} → unexpected severity {r.severity!r}"


def test_executor_correlation_rules_have_window_and_sql():
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    corr = [r for r in ex.rules if r.is_correlation]
    assert corr, "En az bir correlation rule yüklenmeli"
    for r in corr:
        assert r.window_seconds > 0
        assert "HAVING" in r.sql
        assert "normalized_logs" in r.sql


def test_executor_output_event_action_auto_generated():
    r = SigmaExecutableRule(
        rule_id="abc", title="Windows Brute Force Test",
        severity="high", sql="SELECT 1",
        window_seconds=300, group_by_fields=["source_ip"],
        is_correlation=True,
    )
    assert r.output_event_action == "windows_brute_force_test_detected"


def test_executor_output_event_action_explicit():
    r = SigmaExecutableRule(
        rule_id="abc", title="Some Rule",
        severity="high", sql="SELECT 1",
        window_seconds=60, group_by_fields=[],
        is_correlation=False,
        output_event_action="custom_action",
    )
    assert r.output_event_action == "custom_action"


# ------------------------------------------------------------------ #
#  New V2 rule files — içerik doğrulaması
# ------------------------------------------------------------------ #

def test_device_and_snmp_rules_load():
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    titles = {r.title for r in ex.rules}
    assert "Device Sustained Outage" in titles
    assert "SNMP Trap Burst" in titles


def test_windows_event_rules_load():
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    titles = {r.title for r in ex.rules}
    assert "Windows Brute Force" in titles
    assert "Windows Password Spray" in titles
    assert "Windows Pass-the-Hash" in titles
    assert "Windows Lateral Movement" in titles
    assert "Windows Suspicious Process" in titles


def test_auth_and_web_rules_load():
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    titles = {r.title for r in ex.rules}
    assert "SSH Successful Login" in titles
    assert "Web Scan — HTTP Flood" in titles


def test_dns_burst_rule_loads():
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    titles = {r.title for r in ex.rules}
    assert "DNS Query Burst" in titles


def test_icmp_flood_uses_icmp_flood_attempt_action():
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    raw = (Path(__file__).parent.parent / "config" / "sigma_rules_v2" / "network_community.yml").read_text()
    assert "icmp_flood_attempt" in raw


# ------------------------------------------------------------------ #
#  Routes sigma endpoints
# ------------------------------------------------------------------ #

def test_sigma_list_endpoint_returns_rules(tmp_db, admin_token):
    from fastapi.testclient import TestClient
    from server.main import app
    client = TestClient(app)
    resp = client.get("/api/v1/sigma/rules", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert "rules" in data
    assert "count" in data
    assert data["count"] >= 1


def test_sigma_validate_endpoint_accepts_valid_yaml(tmp_db, admin_token):
    from fastapi.testclient import TestClient
    from server.main import app
    client = TestClient(app)
    resp = client.post(
        "/api/v1/sigma/rules/validate",
        json={"yaml_content": VALID_V2_YAML},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["title"] == "SSH Brute Force Test"
    assert data["is_correlation"] is True


def test_sigma_validate_endpoint_rejects_invalid_yaml(tmp_db, admin_token):
    from fastapi.testclient import TestClient
    from server.main import app
    client = TestClient(app)
    resp = client.post(
        "/api/v1/sigma/rules/validate",
        json={"yaml_content": "not: [valid"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


def test_sigma_upload_and_delete_roundtrip(tmp_db, admin_token, tmp_path, monkeypatch):
    """Upload → list → delete akışı."""
    from fastapi.testclient import TestClient
    import server.routes.sigma as sigma_route
    from server.main import app

    monkeypatch.setattr(sigma_route, "SIGMA_DIR", tmp_path)

    client = TestClient(app)
    headers = {"Authorization": f"Bearer {admin_token}"}

    upload_resp = client.post(
        "/api/v1/sigma/rules",
        json={"yaml_content": VALID_V2_YAML},
        headers=headers,
    )
    assert upload_resp.status_code == 200
    saved_id = upload_resp.json()["saved"]
    assert saved_id == "11111111-2222-3333-4444-555555555555"

    get_resp = client.get(f"/api/v1/sigma/rules/{saved_id}", headers=headers)
    assert get_resp.status_code == 200
    assert "SSH Brute Force Test" in get_resp.json()["yaml_content"]

    del_resp = client.delete(f"/api/v1/sigma/rules/{saved_id}", headers=headers)
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] == saved_id


def test_sigma_delete_nonexistent_returns_404(tmp_db, admin_token, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import server.routes.sigma as sigma_route
    from server.main import app

    monkeypatch.setattr(sigma_route, "SIGMA_DIR", tmp_path)

    client = TestClient(app)
    resp = client.delete(
        "/api/v1/sigma/rules/nonexistent-rule-id",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
