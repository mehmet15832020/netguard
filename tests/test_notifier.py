"""Notifier testleri — correlated event bildirimi."""

from unittest.mock import patch, MagicMock
from server.notifier import Notifier
from shared.models import CorrelatedEvent


def _make_event(**kwargs) -> CorrelatedEvent:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    defaults = dict(
        corr_id="test-corr-001",
        rule_id="ssh_brute_force",
        rule_name="SSH Brute Force",
        event_type="brute_force_detected",
        severity="critical",
        group_value="192.168.1.100",
        matched_count=5,
        window_seconds=60,
        first_seen=now,
        last_seen=now,
        message="SSH Brute Force tespit edildi",
    )
    defaults.update(kwargs)
    return CorrelatedEvent(**defaults)


class TestNotifierCorrelated:
    def test_notify_correlated_calls_webhook_when_enabled(self):
        n = Notifier()
        n.webhook.enabled = True
        n.webhook.webhook_url = "http://localhost:9999/webhook"
        n.webhook.webhook_type = "discord"

        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, raise_for_status=lambda: None)
            n.notify_correlated(_make_event())

        mock_post.assert_called_once()
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "embeds" in payload

    def test_notify_correlated_skips_when_disabled(self):
        n = Notifier()
        n.webhook.enabled = False
        n.email.enabled = False

        with patch("httpx.post") as mock_post:
            n.notify_correlated(_make_event())
            mock_post.assert_not_called()

    def test_slack_payload_format(self):
        n = Notifier()
        n.webhook.enabled = True
        n.webhook.webhook_url = "http://localhost:9999/webhook"
        n.webhook.webhook_type = "slack"

        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, raise_for_status=lambda: None)
            n.notify_correlated(_make_event())

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "text" in payload
