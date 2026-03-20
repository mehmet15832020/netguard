"""
Server endpoint testleri.
TestClient ile gerçek HTTP isteği simüle edilir — uvicorn gerekmez.
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from server.main import app
from server.storage import storage
from shared.models import AgentRegistration, MetricSnapshot, CPUMetrics, MemoryMetrics

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_storage():
    """Her testten önce storage'ı temizle — testler birbirini etkilemesin."""
    storage._agents.clear()
    yield
    storage._agents.clear()


def make_snapshot(agent_id: str = "test-agent-001", hostname: str = "test-host") -> dict:
    """Test için örnek snapshot dict'i."""
    return MetricSnapshot(
        agent_id=agent_id,
        hostname=hostname,
        collected_at=datetime.now(timezone.utc),
        cpu=CPUMetrics(usage_percent=25.0, core_count=4, load_avg_1m=0.5),
        memory=MemoryMetrics(
            total_bytes=8_000_000_000,
            used_bytes=2_000_000_000,
            available_bytes=6_000_000_000,
        ),
    ).model_dump(mode="json")


class TestHealthEndpoint:
    def test_health_returns_ok(self):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "timestamp" in data
        assert data["registered_agents"] == 0


class TestAgentRegistration:
    def test_register_agent_success(self):
        payload = AgentRegistration(
            agent_id="agent-001",
            hostname="test-machine",
            os_name="Linux",
            os_version="6.8.0",
            python_version="3.12.3",
        ).model_dump(mode="json")

        response = client.post("/api/v1/agents/register", json=payload)
        assert response.status_code == 201
        assert response.json()["agent_id"] == "agent-001"

    def test_register_updates_existing_agent(self):
        payload = AgentRegistration(
            agent_id="agent-001",
            hostname="test-machine",
            os_name="Linux",
            os_version="6.8.0",
            python_version="3.12.3",
        ).model_dump(mode="json")

        client.post("/api/v1/agents/register", json=payload)
        client.post("/api/v1/agents/register", json=payload)

        response = client.get("/api/v1/agents")
        assert response.json()["count"] == 1  # İki kez kayıt = hâlâ 1 agent


class TestMetricsEndpoint:
    def test_receive_metrics_accepted(self):
        response = client.post("/api/v1/agents/metrics", json=make_snapshot())
        assert response.status_code == 202
        assert response.json()["status"] == "accepted"

    def test_latest_snapshot_retrievable(self):
        snapshot = make_snapshot(agent_id="agent-abc")
        client.post("/api/v1/agents/metrics", json=snapshot)

        response = client.get("/api/v1/agents/agent-abc/latest")
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "agent-abc"
        assert data["cpu"]["usage_percent"] == 25.0

    def test_unknown_agent_returns_404(self):
        response = client.get("/api/v1/agents/nonexistent/latest")
        assert response.status_code == 404

    def test_history_returns_multiple_snapshots(self):
        for _ in range(5):
            client.post("/api/v1/agents/metrics", json=make_snapshot(agent_id="agent-hist"))

        response = client.get("/api/v1/agents/agent-hist/history?limit=10")
        assert response.status_code == 200
        assert response.json()["count"] == 5