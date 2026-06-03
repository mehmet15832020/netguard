"""N8 — Cloud Audit Log Parser testleri.

server/parsers/cloud.py:
  parse_m365_event() — Office 365 Management Activity API event → NormalizedLog
  parse_gws_event()  — Google Workspace Reports API activity → NormalizedLog
"""

from datetime import datetime, timezone

import pytest

from server.parsers.cloud import parse_m365_event, parse_gws_event


# ── Microsoft 365 ─────────────────────────────────────────────────────────────

_M365_INBOX_RULE = {
    "CreationTime": "2024-06-01T10:00:00Z",
    "Operation":    "New-InboxRule",
    "UserId":       "attacker@victim.com",
    "ClientIP":     "1.2.3.4",
    "Workload":     "Exchange",
    "RecordType":   1,
    "ObjectId":     "inbox-rule-id",
}

_M365_LOGIN_FAIL = {
    "CreationTime": "2024-06-01T11:00:00Z",
    "Operation":    "UserLoginFailed",
    "UserId":       "user@victim.com",
    "ClientIP":     "5.6.7.8",
    "Workload":     "AzureActiveDirectory",
}

_M365_FILE_DL = {
    "CreationTime": "2024-06-01T12:00:00Z",
    "Operation":    "FileDownloaded",
    "UserId":       "user@victim.com",
    "ClientIP":     "9.10.11.12",
    "Workload":     "SharePoint",
    "SiteUrl":      "https://victim.sharepoint.com/sites/data",
}

_M365_UNKNOWN = {
    "CreationTime": "2024-06-01T13:00:00Z",
    "Operation":    "SomeOtherOperation",
    "UserId":       "user@victim.com",
    "Workload":     "Exchange",
}


class TestM365Parser:
    def test_inbox_rule_action(self):
        log = parse_m365_event(_M365_INBOX_RULE)
        assert log.event_action == "m365_inbox_rule"

    def test_inbox_rule_severity_high(self):
        log = parse_m365_event(_M365_INBOX_RULE)
        assert log.severity == "high"

    def test_login_failure_action(self):
        log = parse_m365_event(_M365_LOGIN_FAIL)
        assert log.event_action == "m365_login_failure"

    def test_login_failure_category_auth(self):
        log = parse_m365_event(_M365_LOGIN_FAIL)
        assert log.event_category == "authentication"

    def test_file_download_action(self):
        log = parse_m365_event(_M365_FILE_DL)
        assert log.event_action == "m365_bulk_download"

    def test_source_type_m365(self):
        log = parse_m365_event(_M365_INBOX_RULE)
        assert log.source_type == "m365"

    def test_source_ip_extracted(self):
        log = parse_m365_event(_M365_INBOX_RULE)
        assert log.source_ip == "1.2.3.4"

    def test_ipv4_port_stripped(self):
        event = {**_M365_INBOX_RULE, "ClientIP": "1.2.3.4:54321"}
        log = parse_m365_event(event)
        assert log.source_ip == "1.2.3.4"

    def test_unknown_operation_is_info(self):
        log = parse_m365_event(_M365_UNKNOWN)
        assert log.event_action == "m365_event"
        assert log.severity == "info"

    def test_message_contains_user(self):
        log = parse_m365_event(_M365_INBOX_RULE)
        assert "attacker@victim.com" in log.message

    def test_extra_contains_operation(self):
        log = parse_m365_event(_M365_INBOX_RULE)
        assert log.extra["operation"] == "New-InboxRule"

    def test_timestamp_parsed(self):
        log = parse_m365_event(_M365_INBOX_RULE)
        assert log.timestamp.year == 2024

    def test_observer_hostname(self):
        log = parse_m365_event(_M365_INBOX_RULE, observer_hostname="m365-abc12345")
        assert log.observer_hostname == "m365-abc12345"

    def test_mailbox_permission_action(self):
        event = {**_M365_INBOX_RULE, "Operation": "Add-MailboxPermission"}
        log = parse_m365_event(event)
        assert log.event_action == "m365_mailbox_permission"
        assert log.severity == "high"


# ── Google Workspace ──────────────────────────────────────────────────────────

_GWS_LOGIN_FAIL = {
    "id": {"time": "2024-06-01T10:00:00Z", "applicationName": "login"},
    "actor": {"email": "user@company.com", "ipAddress": "1.2.3.4"},
    "events": [{"name": "login_failure", "parameters": []}],
}

_GWS_SUSPICIOUS = {
    "id": {"time": "2024-06-01T11:00:00Z", "applicationName": "login"},
    "actor": {"email": "user@company.com", "ipAddress": "5.6.7.8"},
    "events": [{"name": "suspicious_login", "parameters": []}],
}

_GWS_GMAIL_RULE = {
    "id": {"time": "2024-06-01T12:00:00Z", "applicationName": "admin"},
    "actor": {"email": "user@company.com", "ipAddress": "9.10.11.12"},
    "events": [{"name": "change_gmail_setting", "parameters": [
        {"name": "SETTING_NAME", "value": "FORWARDING_RULE"}
    ]}],
}

_GWS_ADMIN_PRIV = {
    "id": {"time": "2024-06-01T13:00:00Z", "applicationName": "admin"},
    "actor": {"email": "attacker@company.com", "ipAddress": "1.1.1.1"},
    "events": [{"name": "GRANT_ADMIN_PRIVILEGE", "parameters": []}],
}

_GWS_DOWNLOAD = {
    "id": {"time": "2024-06-01T14:00:00Z", "applicationName": "drive"},
    "actor": {"email": "user@company.com", "ipAddress": "2.2.2.2"},
    "events": [{"name": "download", "parameters": [{"name": "doc_title", "value": "secret.xlsx"}]}],
}

_GWS_UNKNOWN = {
    "id": {"time": "2024-06-01T15:00:00Z", "applicationName": "calendar"},
    "actor": {"email": "user@company.com"},
    "events": [{"name": "create_event", "parameters": []}],
}


class TestGWSParser:
    def test_login_failure_action(self):
        log = parse_gws_event(_GWS_LOGIN_FAIL)
        assert log.event_action == "gws_login_failure"

    def test_login_failure_category_auth(self):
        log = parse_gws_event(_GWS_LOGIN_FAIL)
        assert log.event_category == "authentication"

    def test_suspicious_login_high(self):
        log = parse_gws_event(_GWS_SUSPICIOUS)
        assert log.event_action == "gws_suspicious_login"
        assert log.severity == "high"

    def test_gmail_rule_action(self):
        log = parse_gws_event(_GWS_GMAIL_RULE)
        assert log.event_action == "gws_gmail_rule"
        assert log.severity == "high"

    def test_admin_privilege_action(self):
        log = parse_gws_event(_GWS_ADMIN_PRIV)
        assert log.event_action == "gws_admin_privilege"

    def test_bulk_download_action(self):
        log = parse_gws_event(_GWS_DOWNLOAD)
        assert log.event_action == "gws_bulk_download"

    def test_source_type_gworkspace(self):
        log = parse_gws_event(_GWS_LOGIN_FAIL)
        assert log.source_type == "gworkspace"

    def test_source_ip_extracted(self):
        log = parse_gws_event(_GWS_LOGIN_FAIL)
        assert log.source_ip == "1.2.3.4"

    def test_no_ip_returns_none(self):
        log = parse_gws_event(_GWS_UNKNOWN)
        assert log.source_ip is None

    def test_unknown_event_is_info(self):
        log = parse_gws_event(_GWS_UNKNOWN)
        assert log.event_action == "gws_event"
        assert log.severity == "info"

    def test_message_contains_user(self):
        log = parse_gws_event(_GWS_LOGIN_FAIL)
        assert "user@company.com" in log.message

    def test_timestamp_parsed(self):
        log = parse_gws_event(_GWS_LOGIN_FAIL)
        assert log.timestamp.year == 2024

    def test_extra_contains_application(self):
        log = parse_gws_event(_GWS_LOGIN_FAIL)
        assert log.extra["application"] == "login"

    def test_params_extracted_to_extra(self):
        log = parse_gws_event(_GWS_GMAIL_RULE)
        assert log.extra["params"].get("SETTING_NAME") == "FORWARDING_RULE"

    def test_observer_hostname(self):
        log = parse_gws_event(_GWS_LOGIN_FAIL, observer_hostname="gws-company.com")
        assert log.observer_hostname == "gws-company.com"
