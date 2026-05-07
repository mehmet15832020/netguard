"""Notifier testleri — correlated event ve anomaly bildirimi."""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock, call
from server.notifier import Notifier, EmailNotifier, WebhookNotifier
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


def _make_anomaly(severity="critical", entity_id="server-1", metric="cpu") -> "AnomalyResult":
    from server.anomaly.models import AnomalyResult
    return AnomalyResult(
        result_id=str(uuid.uuid4()),
        entity_id=entity_id,
        metric=metric,
        observed_value=95.0,
        baseline_mean=40.0,
        baseline_std=5.0,
        z_score=11.0,
        severity=severity,
        confidence=0.95,
        message=f"Anomali: {entity_id} — {metric} = 95.0 (baseline 40.0±5.0, z=11.0σ)",
        detected_at=datetime.now(timezone.utc),
    )


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


class TestNotifierAnomaly:
    def test_notify_anomaly_sends_webhook(self):
        n = Notifier()
        n.webhook.enabled = True
        n.webhook.webhook_url = "http://localhost:9999/webhook"
        n.webhook.webhook_type = "discord"

        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, raise_for_status=lambda: None)
            n.notify_anomaly(_make_anomaly(severity="critical"))

        mock_post.assert_called_once()
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "embeds" in payload
        assert "Anomali" in payload["embeds"][0]["title"]

    def test_notify_anomaly_below_min_severity_skipped(self):
        n = Notifier()
        n.webhook.enabled = True

        with patch("httpx.post") as mock_post:
            with patch.object(n, "_get_min_severity", return_value="critical"):
                n.notify_anomaly(_make_anomaly(severity="warning"))
        mock_post.assert_not_called()

    def test_notify_anomaly_cooldown_prevents_spam(self):
        n = Notifier()
        n.webhook.enabled = True
        n.webhook.webhook_url = "http://localhost:9999/webhook"
        n.webhook.webhook_type = "discord"

        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, raise_for_status=lambda: None)
            with patch.object(n, "_get_min_severity", return_value="warning"):
                n.notify_anomaly(_make_anomaly(severity="critical"))
                n.notify_anomaly(_make_anomaly(severity="critical"))

        assert mock_post.call_count == 1  # İkincisi cooldown'da bloklanmalı

    def test_notify_anomaly_cooldown_different_metrics_both_sent(self):
        n = Notifier()
        n.webhook.enabled = True
        n.webhook.webhook_url = "http://localhost:9999/webhook"
        n.webhook.webhook_type = "discord"

        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, raise_for_status=lambda: None)
            with patch.object(n, "_get_min_severity", return_value="warning"):
                n.notify_anomaly(_make_anomaly(metric="cpu"))
                n.notify_anomaly(_make_anomaly(metric="memory"))

        assert mock_post.call_count == 2  # Farklı metrikler — iki bildirim gitmeli

    def test_notify_anomaly_cooldown_expires(self):
        n = Notifier()
        n.webhook.enabled = True
        n.webhook.webhook_url = "http://localhost:9999/webhook"
        n.webhook.webhook_type = "discord"

        past = datetime.now(timezone.utc) - timedelta(hours=2)
        n._anomaly_cooldown["server-1:cpu"] = past

        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, raise_for_status=lambda: None)
            with patch.object(n, "_get_min_severity", return_value="warning"):
                n.notify_anomaly(_make_anomaly(severity="critical"))

        mock_post.assert_called_once()  # Cooldown geçti — gönderilmeli

    def test_notify_anomaly_slack_format(self):
        n = Notifier()
        n.webhook.enabled = True
        n.webhook.webhook_url = "http://localhost:9999/webhook"
        n.webhook.webhook_type = "slack"

        with patch("httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200, raise_for_status=lambda: None)
            with patch.object(n, "_get_min_severity", return_value="warning"):
                n.notify_anomaly(_make_anomaly())

        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1].get("json")
        assert "text" in payload
        assert "Anomali" in payload["text"]

    def test_notify_anomaly_webhook_retries_on_failure(self):
        """Anomaly webhook geçici hata sonrası yeniden dener."""
        n = Notifier()
        n.webhook.enabled = True
        n.webhook.webhook_url = "http://localhost:9999/webhook"
        n.webhook.webhook_type = "discord"

        ok = MagicMock(status_code=200, raise_for_status=lambda: None)
        with patch("httpx.post", side_effect=[Exception("timeout"), ok]) as mock_post:
            with patch("time.sleep"):
                with patch.object(n, "_get_min_severity", return_value="warning"):
                    n.notify_anomaly(_make_anomaly())

        assert mock_post.call_count == 2

    def test_notify_anomaly_email_retries_on_failure(self):
        """Anomaly email geçici SMTP hatası sonrası yeniden dener."""
        import smtplib
        n = Notifier()
        n.email.enabled = True
        n.email.smtp_host = "smtp.test"
        n.email.smtp_port = 587
        n.email.smtp_user = "u"
        n.email.smtp_password = "p"
        n.email.from_email = "u@test"
        n.email.to_emails = ["dest@test"]

        call_count = {"n": 0}

        class _FakeSMTP:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def starttls(self): pass
            def login(self, *a): pass
            def send_message(self, msg):
                call_count["n"] += 1
                if call_count["n"] < 2:
                    raise smtplib.SMTPException("transient")

        with patch("smtplib.SMTP", return_value=_FakeSMTP()):
            with patch("time.sleep"):
                with patch.object(n, "_get_min_severity", return_value="warning"):
                    n.notify_anomaly(_make_anomaly())

        assert call_count["n"] == 2


class TestRetryHelpers:
    """EmailNotifier._send_msg ve WebhookNotifier._post_payload retry davranışı."""

    def test_webhook_succeeds_on_first_try(self):
        w = WebhookNotifier()
        w.enabled = True
        w.webhook_url = "http://x"
        ok = MagicMock(raise_for_status=lambda: None)
        with patch("httpx.post", return_value=ok) as mock_post:
            result = w._post_payload({"x": 1}, "ctx")
        assert result is True
        assert mock_post.call_count == 1

    def test_webhook_retries_twice_then_fails(self):
        w = WebhookNotifier()
        w.enabled = True
        w.webhook_url = "http://x"
        with patch("httpx.post", side_effect=Exception("err")) as mock_post:
            with patch("time.sleep"):
                result = w._post_payload({"x": 1}, "ctx")
        assert result is False
        assert mock_post.call_count == 3

    def test_webhook_succeeds_on_second_try(self):
        w = WebhookNotifier()
        w.enabled = True
        w.webhook_url = "http://x"
        ok = MagicMock(raise_for_status=lambda: None)
        with patch("httpx.post", side_effect=[Exception("err"), ok]) as mock_post:
            with patch("time.sleep"):
                result = w._post_payload({"x": 1}, "ctx")
        assert result is True
        assert mock_post.call_count == 2
