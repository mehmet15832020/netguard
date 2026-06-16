"""
A1 — MetricSender X-API-Key header testleri.

Server tarafı /agents/metrics artık API key zorunlu kılıyor (server/routes/agents.py).
Bu testler agent'ın gerçekten X-API-Key header'ı gönderdiğini doğrular —
sunucu fix'i agent tarafı güncellenmeden production'da agent'ı 401'e düşürür.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from agent.sender import MetricSender
from shared.models import CPUMetrics, MemoryMetrics, MetricSnapshot


def _make_snapshot() -> MetricSnapshot:
    return MetricSnapshot(
        agent_id="test-agent-001",
        hostname="test-host",
        collected_at=datetime.now(timezone.utc),
        cpu=CPUMetrics(usage_percent=10.0, core_count=4, load_avg_1m=0.2),
        memory=MemoryMetrics(
            total_bytes=8_000_000_000,
            used_bytes=2_000_000_000,
            available_bytes=6_000_000_000,
        ),
    )


class TestSendSnapshotApiKeyHeader:
    def test_sends_x_api_key_header(self):
        sender = MetricSender(server_url="http://localhost:8000", api_key="secret-key-123")
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None

        with patch.object(sender._client, "post", return_value=mock_response) as mock_post:
            assert sender.send_snapshot(_make_snapshot()) is True

        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["X-API-Key"] == "secret-key-123"

    def test_warns_when_api_key_missing(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="agent.sender"):
            MetricSender(server_url="http://localhost:8000", api_key="")
        assert "NETGUARD_API_KEY" in caplog.text

    def test_default_api_key_is_empty_string(self):
        sender = MetricSender(server_url="http://localhost:8000")
        assert sender._api_key == ""


class TestSenderTlsVerification:
    def test_verifies_tls_by_default(self, monkeypatch):
        monkeypatch.delenv("NETGUARD_CA_BUNDLE", raising=False)
        monkeypatch.delenv("NETGUARD_VERIFY_TLS", raising=False)
        with patch("agent.sender.httpx.Client") as mock_client:
            MetricSender(server_url="https://localhost:8000")
        assert mock_client.call_args.kwargs["verify"] is True

    def test_verify_false_passed_through_when_disabled(self, monkeypatch):
        monkeypatch.delenv("NETGUARD_CA_BUNDLE", raising=False)
        monkeypatch.setenv("NETGUARD_VERIFY_TLS", "false")
        with patch("agent.sender.httpx.Client") as mock_client:
            MetricSender(server_url="https://localhost:8000")
        assert mock_client.call_args.kwargs["verify"] is False

    def test_ca_bundle_path_passed_through(self, monkeypatch):
        monkeypatch.setenv("NETGUARD_CA_BUNDLE", "/etc/netguard/ca.pem")
        with patch("agent.sender.httpx.Client") as mock_client:
            MetricSender(server_url="https://localhost:8000")
        assert mock_client.call_args.kwargs["verify"] == "/etc/netguard/ca.pem"
