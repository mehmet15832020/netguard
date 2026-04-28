"""
Attack chain API endpoint testleri.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from shared.models import CorrelatedEvent


def _make_chain_event(rule_id="full_attack_chain", severity="critical", group_value="10.0.0.5"):
    now = datetime.now(timezone.utc)
    return CorrelatedEvent(
        corr_id       = str(uuid.uuid4()),
        rule_id       = rule_id,
        rule_name     = rule_id.replace("_", " ").title(),
        event_type    = rule_id + "_detected",
        severity      = severity,
        group_value   = group_value,
        matched_count = 3,
        window_seconds= 1800,
        first_seen    = now,
        last_seen     = now,
        message       = f"Test chain {group_value}",
    )


class TestAttackChainsEndpoints:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_db):
        from server.main import app
        self.client = TestClient(app)
        self.db = tmp_db

    def test_active_chains_empty(self, admin_token):
        with patch("server.routes.attack_chains.attack_chain_tracker") as mock_tracker:
            mock_tracker.get_chains.return_value = {}
            resp = self.client.get(
                "/api/v1/attack-chains/active",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["chains"] == []

    def test_active_chains_returns_enriched(self, admin_token):
        mock_chains = {
            "192.168.1.5": {"recon": 3, "weaponize": 5, "access": 1},
        }
        with patch("server.routes.attack_chains.attack_chain_tracker") as mock_tracker:
            mock_tracker.get_chains.return_value = mock_chains
            resp = self.client.get(
                "/api/v1/attack-chains/active",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        chain = data["chains"][0]
        assert chain["src_ip"] == "192.168.1.5"
        assert chain["stage_count"] == 3
        assert chain["severity"] == "critical"
        assert chain["chain_type"] == "FULL_ATTACK_CHAIN"

    def test_partial_chain_gets_warning_severity(self, admin_token):
        mock_chains = {"10.0.0.1": {"recon": 2, "weaponize": 1}}
        with patch("server.routes.attack_chains.attack_chain_tracker") as mock_tracker:
            mock_tracker.get_chains.return_value = mock_chains
            resp = self.client.get(
                "/api/v1/attack-chains/active",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert resp.status_code == 200
        chain = resp.json()["chains"][0]
        assert chain["severity"] == "warning"
        assert chain["chain_type"] == "PARTIAL_ATTACK_CHAIN"

    def test_history_returns_chain_events(self, admin_token):
        ev = _make_chain_event()
        self.db.save_correlated_event(ev)

        with patch("server.routes.attack_chains.attack_chain_tracker") as mock_tracker:
            mock_tracker.get_chains.return_value = {}
            resp = self.client.get(
                "/api/v1/attack-chains/history",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        assert any(e["rule_id"] == "full_attack_chain" for e in data["events"])

    def test_history_excludes_non_chain_events(self, admin_token):
        # Save a non-chain event
        other = _make_chain_event(rule_id="port_scan_detected", severity="info")
        self.db.save_correlated_event(other)

        resp = self.client.get(
            "/api/v1/attack-chains/history",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        events = resp.json()["events"]
        for e in events:
            assert e["rule_id"] in {"full_attack_chain", "partial_attack_chain"}

    def test_stats_returns_expected_keys(self, admin_token):
        with patch("server.routes.attack_chains.attack_chain_tracker") as mock_tracker:
            mock_tracker.get_chains.return_value = {}
            resp = self.client.get(
                "/api/v1/attack-chains/stats",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "active_ips" in data
        assert "chains_24h" in data
        assert "critical_24h" in data
        assert "unique_ips_24h" in data
        assert "stage_distribution" in data
