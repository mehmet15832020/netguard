"""
Windows event dict → NormalizedLog dönüşümcüsü.

evtx_parser._parse_record_xml() çıktısını alır, normalized_logs tablosuna
yazılmak üzere NormalizedLog üretir.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from shared.models import NormalizedLog, LogSourceType, LogCategory

_ACTION_TO_CATEGORY: dict[str, LogCategory] = {
    # Authentication
    "windows_logon_success":         LogCategory.AUTHENTICATION,
    "windows_logon_failure":         LogCategory.AUTHENTICATION,
    "windows_explicit_logon":        LogCategory.AUTHENTICATION,
    "windows_kerberos_tgt":          LogCategory.AUTHENTICATION,
    "windows_kerberos_service":      LogCategory.AUTHENTICATION,
    "windows_kerberos_preauth_fail": LogCategory.AUTHENTICATION,
    "windows_ntlm_auth":             LogCategory.AUTHENTICATION,
    "windows_account_lockout":       LogCategory.AUTHENTICATION,
    "windows_user_created":          LogCategory.AUTHENTICATION,
    "windows_group_member_added":    LogCategory.AUTHENTICATION,
    "windows_special_priv":          LogCategory.AUTHENTICATION,
    # System / Execution
    "windows_process_create":        LogCategory.SYSTEM,
    "windows_task_created":          LogCategory.SYSTEM,
    "windows_task_updated":          LogCategory.SYSTEM,
    "windows_log_cleared":           LogCategory.SYSTEM,
    "windows_sysmon_process":        LogCategory.SYSTEM,
    "windows_sysmon_proc_access":    LogCategory.INTRUSION,
    "windows_sysmon_driver_load":    LogCategory.INTRUSION,
    "windows_sysmon_image_load":     LogCategory.SYSTEM,
    "windows_sysmon_file_create":    LogCategory.SYSTEM,
    "windows_sysmon_registry":       LogCategory.SYSTEM,
    # Network
    "windows_sysmon_network":        LogCategory.NETWORK,
    "windows_sysmon_dns":            LogCategory.NETWORK,
    "windows_share_access":          LogCategory.NETWORK,
    # Security yeni
    "windows_lateral_logon":           LogCategory.AUTHENTICATION,
    "windows_computer_account_changed": LogCategory.AUTHENTICATION,
    "windows_logon_process_registered": LogCategory.INTRUSION,
    "windows_token_privilege_adjusted": LogCategory.AUTHENTICATION,
    # PowerShell
    "windows_powershell_module":       LogCategory.SYSTEM,
    "windows_powershell_scriptblock":  LogCategory.INTRUSION,
    # System channel
    "windows_service_installed":       LogCategory.SYSTEM,
    "windows_service_crashed":         LogCategory.SYSTEM,
    "windows_service_start_changed":   LogCategory.SYSTEM,
    # AppLocker
    "windows_applocker_blocked":       LogCategory.INTRUSION,
    # Sysmon yeni
    "windows_sysmon_remote_thread":    LogCategory.INTRUSION,
    "windows_sysmon_raw_access":       LogCategory.INTRUSION,
    "windows_sysmon_ads":              LogCategory.INTRUSION,
    "windows_sysmon_pipe_created":     LogCategory.INTRUSION,
    "windows_sysmon_pipe_connected":   LogCategory.INTRUSION,
    "windows_sysmon_wmi_event":        LogCategory.INTRUSION,
    "windows_sysmon_wmi_binding":      LogCategory.INTRUSION,
    "windows_sysmon_process_tamper":   LogCategory.INTRUSION,
}


def to_normalized_log(rec: dict) -> Optional[NormalizedLog]:
    """
    evtx_parser dict'ini NormalizedLog'a çevirir.
    Döner: NormalizedLog | None (gerekli alanlar eksikse).
    """
    event_action = rec.get("event_action", "")
    if not event_action:
        return None

    occurred_at_str = rec.get("occurred_at", "")
    try:
        ts = datetime.fromisoformat(occurred_at_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        ts = datetime.now(timezone.utc)

    category = _ACTION_TO_CATEGORY.get(event_action, LogCategory.UNKNOWN)

    dst_port = rec.get("destination_port")
    if dst_port is not None:
        try:
            dst_port = int(dst_port)
        except (TypeError, ValueError):
            dst_port = None

    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.WINDOWS,
        observer_hostname=rec.get("observer_hostname", "windows"),
        timestamp=ts,
        severity=rec.get("severity", "info"),
        event_category=category,
        event_action=event_action,
        source_ip=rec.get("source_ip"),
        destination_ip=rec.get("destination_ip"),
        destination_port=dst_port,
        network_protocol=rec.get("network_protocol"),
        username=rec.get("username"),
        message=rec.get("message", ""),
        tags=["windows", "evtx"],
    )
