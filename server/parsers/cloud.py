"""
NetGuard — Cloud Audit Log Parser

Microsoft 365 (Office 365 Management Activity API) ve
Google Workspace (Admin Reports API) eventlerini NormalizedLog'a dönüştürür.

BEC odaklı: inbox rules, mailbox permissions, delegate access,
bulk downloads, admin privilege escalation.

Kaynaklar: MITRE ATT&CK T1114/T1098/T1530/T1110/T1078, SANS FOR508, RFC 7519
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

# Namespace UUID for deterministic log_id — aynı cloud event'in tekrar
# işlenmesinde aynı log_id üretilir (overlap window duplicate koruması).
_CLOUD_NS = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

from shared.models import LogCategory, LogSourceType, NormalizedLog

logger = logging.getLogger(__name__)


# ── Microsoft 365 ─────────────────────────────────────────────────────────────

_M365_OPERATIONS: dict[str, tuple[str, str]] = {
    "new-inboxrule":           ("m365_inbox_rule",         "high"),
    "set-inboxrule":           ("m365_inbox_rule",         "high"),
    "add-mailboxpermission":   ("m365_mailbox_permission", "high"),
    "add-recipientpermission": ("m365_mailbox_permission", "high"),
    "mailitemsaccessed":       ("m365_mail_access",        "warning"),
    "user.addredasdelegate":   ("m365_delegate_access",    "high"),
    "add member to role.":     ("m365_role_assignment",    "high"),
    "userloginfailed":         ("m365_login_failure",      "info"),
    "filedownloaded":          ("m365_bulk_download",      "warning"),
}


def _parse_iso(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def _extract_m365_ip(event: dict) -> Optional[str]:
    ip = event.get("ClientIP") or event.get("ActorIpAddress") or ""
    if not ip:
        return None
    # Strip port from IPv4:port notation
    if ip.startswith("["):
        ip = ip.strip("[]").split("]")[0]
    elif ":" in ip and ip.count(":") == 1:
        ip = ip.rsplit(":", 1)[0]
    return ip or None


def parse_m365_event(event: dict, observer_hostname: str = "m365") -> Optional[NormalizedLog]:
    """Office 365 Management Activity API event → NormalizedLog."""
    operation = (event.get("Operation") or "").lower()
    action, severity = _M365_OPERATIONS.get(operation, ("m365_event", "info"))

    user_id = event.get("UserId") or ""
    if not user_id:
        actors = event.get("Actor") or []
        user_id = actors[0].get("ID", "") if actors else ""

    ts_str = event.get("CreationTime") or event.get("CreationDate") or ""
    ts = _parse_iso(ts_str) if ts_str else datetime.now(timezone.utc)

    workload = event.get("Workload") or ""
    op_display = event.get("Operation") or ""
    client_ip = _extract_m365_ip(event)

    msg = f"M365 {workload} {op_display} user={user_id}"
    if client_ip:
        msg += f" ip={client_ip}"

    dedup_key = f"m365:{user_id}:{op_display}:{ts_str}"
    return NormalizedLog(
        log_id            = str(uuid.uuid5(_CLOUD_NS, dedup_key)),
        raw_id            = str(uuid.uuid4()),
        source_type       = LogSourceType.M365,
        observer_hostname = observer_hostname,
        timestamp         = ts,
        severity          = severity,
        event_category    = (LogCategory.AUTHENTICATION
                             if "login" in action
                             else LogCategory.NETWORK),
        event_action      = action,
        source_ip         = client_ip,
        message           = msg,
        tags              = ["m365", workload.lower() if workload else "cloud"],
        extra             = {
            "operation":   op_display,
            "workload":    workload,
            "record_type": event.get("RecordType"),
            "user_id":     user_id,
            "object_id":   event.get("ObjectId") or "",
            "site_url":    event.get("SiteUrl") or "",
        },
    )


# ── Google Workspace ──────────────────────────────────────────────────────────

_GWS_EVENTS: dict[str, tuple[str, str]] = {
    "login_failure":                        ("gws_login_failure",    "info"),
    "suspicious_login":                     ("gws_suspicious_login", "high"),
    "suspicious_login_less_secure_app":     ("gws_suspicious_login", "high"),
    "gov_attack_warning":                   ("gws_suspicious_login", "critical"),
    "change_gmail_setting":                 ("gws_gmail_rule",       "high"),
    "gmail_phishing_config":                ("gws_gmail_rule",       "high"),
    "grant_admin_privilege":                ("gws_admin_privilege",  "high"),
    "assign_role":                          ("gws_admin_privilege",  "high"),
    "add_application_type_custom_rule":     ("gws_gmail_rule",       "high"),
    "download":                             ("gws_bulk_download",    "warning"),
}


def parse_gws_event(event: dict, observer_hostname: str = "gworkspace") -> Optional[NormalizedLog]:
    """Google Workspace Admin Reports API activity event → NormalizedLog."""
    actor     = event.get("actor") or {}
    id_block  = event.get("id") or {}
    sub_events = event.get("events") or [{}]
    sub       = sub_events[0] if sub_events else {}

    user_email   = actor.get("email") or actor.get("profileId") or ""
    ip_address   = actor.get("ipAddress") or ""
    ts_str       = id_block.get("time") or ""
    ts           = _parse_iso(ts_str) if ts_str else datetime.now(timezone.utc)
    application  = id_block.get("applicationName") or ""
    event_name   = (sub.get("name") or "").lower()

    action, severity = _GWS_EVENTS.get(event_name, ("gws_event", "info"))

    params = {
        p.get("name"): (p.get("value") or p.get("boolValue") or p.get("intValue"))
        for p in (sub.get("parameters") or [])
        if p.get("name")
    }

    msg = f"GWorkspace {application} {sub.get('name', '')} user={user_email}"
    if ip_address:
        msg += f" ip={ip_address}"

    dedup_key = f"gws:{user_email}:{ts_str}:{event_name}"
    return NormalizedLog(
        log_id            = str(uuid.uuid5(_CLOUD_NS, dedup_key)),
        raw_id            = str(uuid.uuid4()),
        source_type       = LogSourceType.GWORKSPACE,
        observer_hostname = observer_hostname,
        timestamp         = ts,
        severity          = severity,
        event_category    = (LogCategory.AUTHENTICATION
                             if "login" in action
                             else LogCategory.NETWORK),
        event_action      = action,
        source_ip         = ip_address or None,
        message           = msg,
        tags              = ["gworkspace", application] if application else ["gworkspace"],
        extra             = {
            "application": application,
            "event_name":  sub.get("name") or "",
            "user_email":  user_email,
            "params":      params,
        },
    )
