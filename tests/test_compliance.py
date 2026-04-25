"""Compliance raporu testleri."""

import pytest
from fastapi.testclient import TestClient
from server.main import app
from server.auth import create_access_token
from server.compliance import (
    evaluate_compliance,
    ALL_CONTROLS,
    PCI_CONTROLS,
    ISO_CONTROLS,
    _score_control,
    _collect_metrics,
)

client = TestClient(app)


def _auth():
    token = create_access_token(username="admin", role="admin")
    return {"Authorization": f"Bearer {token}"}


class TestComplianceControls:
    def test_pci_controls_exist(self):
        assert len(PCI_CONTROLS) >= 5
        ids = [c.control_id for c in PCI_CONTROLS]
        assert any(i.startswith("PCI-") for i in ids)

    def test_iso_controls_exist(self):
        assert len(ISO_CONTROLS) >= 5
        ids = [c.control_id for c in ISO_CONTROLS]
        assert any(i.startswith("ISO-") for i in ids)

    def test_all_controls_have_required_fields(self):
        for c in ALL_CONTROLS:
            assert c.control_id
            assert c.title
            assert c.framework in ("PCI DSS v4.0", "ISO 27001:2022")
            assert len(c.netguard_features) > 0

    def test_control_ids_unique(self):
        ids = [c.control_id for c in ALL_CONTROLS]
        assert len(ids) == len(set(ids))


class TestScoreControl:
    def _make_control(self, check_fn="test_metric"):
        from server.compliance import ComplianceControl
        return ComplianceControl(
            control_id="TEST-1",
            title="Test",
            description="Test",
            framework="PCI DSS v4.0",
            category="Test",
            netguard_features=["feature_a"],
            check_fn=check_fn,
        )

    def test_compliant_when_metric_high(self):
        ctrl = self._make_control("audit_log_count")
        result = _score_control(ctrl, {"audit_log_count": 50})
        assert result.status == "compliant"
        assert result.score == 100

    def test_partial_when_metric_low(self):
        ctrl = self._make_control("audit_log_count")
        result = _score_control(ctrl, {"audit_log_count": 3})
        assert result.status == "partial"
        assert result.score == 50

    def test_gap_when_no_data(self):
        ctrl = self._make_control("audit_log_count")
        result = _score_control(ctrl, {})
        assert result.status == "gap"
        assert result.score == 0

    def test_evidence_populated_when_compliant(self):
        ctrl = self._make_control("correlated_event_count")
        result = _score_control(ctrl, {"correlated_event_count": 20})
        assert len(result.evidence) > 0

    def test_recommendations_populated_when_gap(self):
        ctrl = self._make_control("incident_count")
        result = _score_control(ctrl, {})
        assert len(result.recommendations) > 0


class TestEvaluateCompliance:
    def test_returns_required_keys(self, tmp_db):
        result = evaluate_compliance(tmp_db)
        assert "overall_score" in result
        assert "total_controls" in result
        assert "compliant" in result
        assert "partial" in result
        assert "gaps" in result
        assert "by_framework" in result
        assert "controls" in result

    def test_pci_framework_filter(self, tmp_db):
        result = evaluate_compliance(tmp_db, framework="PCI DSS v4.0")
        for ctrl in result["controls"]:
            assert ctrl["framework"] == "PCI DSS v4.0"

    def test_iso_framework_filter(self, tmp_db):
        result = evaluate_compliance(tmp_db, framework="ISO 27001:2022")
        for ctrl in result["controls"]:
            assert ctrl["framework"] == "ISO 27001:2022"

    def test_total_controls_count(self, tmp_db):
        result = evaluate_compliance(tmp_db)
        assert result["total_controls"] == len(ALL_CONTROLS)

    def test_score_between_0_and_100(self, tmp_db):
        result = evaluate_compliance(tmp_db)
        assert 0 <= result["overall_score"] <= 100

    def test_counts_sum_to_total(self, tmp_db):
        result = evaluate_compliance(tmp_db)
        assert result["compliant"] + result["partial"] + result["gaps"] == result["total_controls"]

    def test_by_framework_has_both(self, tmp_db):
        result = evaluate_compliance(tmp_db)
        assert "PCI DSS v4.0" in result["by_framework"]
        assert "ISO 27001:2022" in result["by_framework"]

    def test_each_control_has_status(self, tmp_db):
        result = evaluate_compliance(tmp_db)
        for ctrl in result["controls"]:
            assert ctrl["status"] in ("compliant", "partial", "gap")


class TestComplianceEndpoints:
    def test_report_requires_auth(self, tmp_db):
        r = client.get("/api/v1/compliance/report")
        assert r.status_code == 401

    def test_report_returns_200(self, tmp_db):
        r = client.get("/api/v1/compliance/report", headers=_auth())
        assert r.status_code == 200
        data = r.json()
        assert "overall_score" in data
        assert "controls" in data

    def test_report_pci_filter(self, tmp_db):
        r = client.get("/api/v1/compliance/report?framework=PCI+DSS+v4.0", headers=_auth())
        assert r.status_code == 200
        data = r.json()
        for ctrl in data["controls"]:
            assert ctrl["framework"] == "PCI DSS v4.0"

    def test_controls_endpoint(self, tmp_db):
        r = client.get("/api/v1/compliance/controls", headers=_auth())
        assert r.status_code == 200
        data = r.json()
        assert "count" in data
        assert data["count"] == len(ALL_CONTROLS)

    def test_summary_endpoint(self, tmp_db):
        r = client.get("/api/v1/compliance/summary", headers=_auth())
        assert r.status_code == 200
        data = r.json()
        assert "pci_dss" in data
        assert "iso_27001" in data
        assert "score" in data["pci_dss"]
        assert "score" in data["iso_27001"]

    def test_summary_scores_in_range(self, tmp_db):
        r = client.get("/api/v1/compliance/summary", headers=_auth())
        data = r.json()
        assert 0 <= data["pci_dss"]["score"] <= 100
        assert 0 <= data["iso_27001"]["score"] <= 100
