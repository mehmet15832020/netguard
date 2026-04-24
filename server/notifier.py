"""
NetGuard — Notifier

Alert oluştuğunda dış kanallara bildirim gönderir.
Şu an desteklenen kanallar: Email (SMTP), Webhook (Discord/Slack)

Tasarım: Alert Engine'den bağımsız. Yeni kanal eklemek için
yalnızca bu dosyaya yeni bir sender fonksiyonu eklemek yeterli.
"""

import logging
import os
import smtplib
import httpx
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

from shared.models import Alert, AlertSeverity, CorrelatedEvent

logger = logging.getLogger(__name__)


class EmailNotifier:
    """SMTP üzerinden email bildirimi gönderir."""

    def __init__(self):
        self.enabled = False
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email = os.getenv("SMTP_FROM", self.smtp_user)
        self.to_emails = os.getenv("SMTP_TO", "").split(",")

        if self.smtp_user and self.smtp_password and self.to_emails[0]:
            self.enabled = True
            logger.info(f"Email bildirimi aktif → {self.to_emails}")
        else:
            logger.info("Email bildirimi devre dışı (SMTP_USER/SMTP_PASSWORD tanımlı değil)")

    def send(self, alert: Alert) -> bool:
        """Alert için email gönderir."""
        if not self.enabled:
            return False

        severity_emoji = {
            AlertSeverity.INFO: "ℹ️",
            AlertSeverity.WARNING: "⚠️",
            AlertSeverity.CRITICAL: "🚨",
        }

        emoji = severity_emoji.get(alert.severity, "⚠️")
        subject = f"{emoji} NetGuard Alert — {alert.severity.upper()}: {alert.hostname}"

        body = f"""
NetGuard Monitoring System — Otomatik Bildirim
{'='*50}

Durum      : {alert.status.upper()}
Seviye     : {alert.severity.upper()}
Makine     : {alert.hostname}
Metrik     : {alert.metric}
Mesaj      : {alert.message}
Değer      : {alert.value}
Eşik       : {alert.threshold}
Zaman      : {alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S UTC')}

{'='*50}
Bu mesaj NetGuard tarafından otomatik olarak gönderilmiştir.
"""

        try:
            msg = MIMEMultipart()
            msg["From"] = self.from_email
            msg["To"] = ", ".join(self.to_emails)
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain", "utf-8"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            logger.info(f"Email gönderildi: {alert.hostname} → {self.to_emails}")
            return True

        except Exception as e:
            logger.error(f"Email gönderilemedi: {e}")
            return False


class WebhookNotifier:
    """Discord veya Slack webhook'una bildirim gönderir."""

    def __init__(self):
        self.enabled = False
        self.webhook_url = os.getenv("WEBHOOK_URL", "")
        self.webhook_type = os.getenv("WEBHOOK_TYPE", "discord").lower()

        if self.webhook_url:
            self.enabled = True
            logger.info(f"Webhook bildirimi aktif → {self.webhook_type}")
        else:
            logger.info("Webhook bildirimi devre dışı (WEBHOOK_URL tanımlı değil)")

    def send(self, alert: Alert) -> bool:
        """Alert için webhook mesajı gönderir."""
        if not self.enabled:
            return False

        try:
            if self.webhook_type == "discord":
                payload = self._discord_payload(alert)
            else:
                payload = self._slack_payload(alert)

            response = httpx.post(self.webhook_url, json=payload, timeout=5)
            response.raise_for_status()
            logger.info(f"Webhook gönderildi: {alert.hostname}")
            return True

        except Exception as e:
            logger.error(f"Webhook gönderilemedi: {e}")
            return False

    def _discord_payload(self, alert: Alert) -> dict:
        """Discord embed formatında payload oluşturur."""
        color_map = {
            AlertSeverity.INFO: 3447003,       # Mavi
            AlertSeverity.WARNING: 16776960,   # Sarı
            AlertSeverity.CRITICAL: 15158332,  # Kırmızı
        }

        return {
            "embeds": [{
                "title": f"🔔 NetGuard Alert — {alert.severity.upper()}",
                "description": alert.message,
                "color": color_map.get(alert.severity, 16776960),
                "fields": [
                    {"name": "Makine", "value": alert.hostname, "inline": True},
                    {"name": "Metrik", "value": alert.metric, "inline": True},
                    {"name": "Değer", "value": str(alert.value), "inline": True},
                    {"name": "Eşik", "value": str(alert.threshold), "inline": True},
                    {"name": "Durum", "value": alert.status.upper(), "inline": True},
                ],
                "footer": {"text": "NetGuard Monitoring System"},
                "timestamp": alert.triggered_at.isoformat(),
            }]
        }

    def _slack_payload(self, alert: Alert) -> dict:
        """Slack Block Kit formatında payload oluşturur."""
        emoji = "🚨" if alert.severity == AlertSeverity.CRITICAL else "⚠️"
        return {
            "text": f"{emoji} *NetGuard Alert — {alert.severity.upper()}*",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *{alert.severity.upper()}: {alert.hostname}*\n{alert.message}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Metrik:*\n{alert.metric}"},
                        {"type": "mrkdwn", "text": f"*Değer:*\n{alert.value}"},
                        {"type": "mrkdwn", "text": f"*Eşik:*\n{alert.threshold}"},
                        {"type": "mrkdwn", "text": f"*Durum:*\n{alert.status.upper()}"},
                    ]
                }
            ]
        }


class Notifier:
    """
    Tüm bildirim kanallarını yöneten ana sınıf.
    Alert Engine bu sınıfla konuşur.
    """

    def __init__(self):
        self.email = EmailNotifier()
        self.webhook = WebhookNotifier()

    def notify(self, alert: Alert) -> None:
        """Alert'i tüm aktif kanallara gönderir. Sadece ACTIVE alertler için."""
        from shared.models import AlertStatus
        if alert.status != AlertStatus.ACTIVE:
            return
        self.email.send(alert)
        self.webhook.send(alert)

    def notify_correlated(self, event: CorrelatedEvent) -> None:
        """Correlated event'i tüm aktif kanallara gönderir. Severity filtresi uygulanır."""
        _SEV = {"info": 0, "warning": 1, "medium": 2, "high": 3, "critical": 4}
        try:
            import json
            from pathlib import Path
            cfg_path = Path(__file__).parent.parent / "config" / "notifier.json"
            min_sev = json.loads(cfg_path.read_text()).get("min_severity", "high")
        except Exception:
            min_sev = "high"
        if _SEV.get(event.severity, 0) < _SEV.get(min_sev, 3):
            return
        self._send_correlated_email(event)
        self._send_correlated_webhook(event)

    def _send_correlated_email(self, event: CorrelatedEvent) -> None:
        if not self.email.enabled:
            return
        severity_prefix = {"critical": "🚨", "high": "🔴", "medium": "🟡", "warning": "⚠️"}.get(event.severity, "ℹ️")
        subject = f"{severity_prefix} NetGuard Korelasyon — {event.severity.upper()}: {event.event_type}"
        body = (
            f"NetGuard Korelasyon Alarmı\n{'='*40}\n\n"
            f"Olay Tipi  : {event.event_type}\n"
            f"Kural      : {event.rule_id} ({event.rule_name})\n"
            f"Seviye     : {event.severity.upper()}\n"
            f"Kaynak     : {event.group_value}\n"
            f"Mesaj      : {event.message}\n"
            f"Eşleşme    : {event.matched_count} olay / {event.window_seconds}s\n"
            f"Zaman      : {event.last_seen}\n\n"
            f"{'='*40}\nBu mesaj NetGuard tarafından otomatik gönderilmiştir.\n"
        )
        try:
            msg = MIMEMultipart()
            msg["From"]    = self.email.from_email
            msg["To"]      = ", ".join(self.email.to_emails)
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain", "utf-8"))
            with smtplib.SMTP(self.email.smtp_host, self.email.smtp_port) as srv:
                srv.starttls()
                srv.login(self.email.smtp_user, self.email.smtp_password)
                srv.send_message(msg)
            logger.info(f"Korelasyon e-postası gönderildi: {event.event_type}")
        except Exception as exc:
            logger.error(f"Korelasyon e-postası gönderilemedi: {exc}")

    def _send_correlated_webhook(self, event: CorrelatedEvent) -> None:
        if not self.webhook.enabled:
            return
        color_map = {"critical": 15158332, "high": 15105570, "medium": 16776960, "warning": 16744272}
        if self.webhook.webhook_type == "discord":
            payload = {
                "embeds": [{
                    "title": f"🔔 NetGuard Korelasyon — {event.severity.upper()}",
                    "description": event.message,
                    "color": color_map.get(event.severity, 16776960),
                    "fields": [
                        {"name": "Olay Tipi", "value": event.event_type,  "inline": True},
                        {"name": "Kural",     "value": event.rule_id,     "inline": True},
                        {"name": "Kaynak",    "value": event.group_value,  "inline": True},
                    ],
                    "footer": {"text": "NetGuard Monitoring System"},
                    "timestamp": event.last_seen.isoformat(),
                }]
            }
        else:
            payload = {
                "text": f"🔔 *NetGuard Korelasyon — {event.severity.upper()}*\n{event.message}"
            }
        try:
            resp = httpx.post(self.webhook.webhook_url, json=payload, timeout=5)
            resp.raise_for_status()
            logger.info(f"Korelasyon webhook gönderildi: {event.event_type}")
        except Exception as exc:
            logger.error(f"Korelasyon webhook gönderilemedi: {exc}")


# Global instance
notifier = Notifier()