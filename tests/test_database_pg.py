"""
PostgreSQL + TimescaleDB entegrasyon testleri (V1-7)

Her test pg_db fixture'ı ile izole bir PostgreSQL veritabanı kullanır.
testcontainers timescale/timescaledb:latest-pg16 imajını çalıştırır.
"""
import uuid
from datetime import datetime, timezone

import pytest

from shared.models import (
    Alert, AlertSeverity, AlertStatus,
    NormalizedLog, LogSourceType, LogCategory,
    CorrelatedEvent,
    Incident, IncidentStatus,
)

pytestmark = pytest.mark.integration


# ── Yardımcı fabrika fonksiyonları ────────────────────────────────────────────

def _uid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _alert(**kwargs) -> Alert:
    defaults = dict(
        alert_id=_uid(),
        agent_id="agent-1",
        hostname="host1",
        severity=AlertSeverity.WARNING,
        status=AlertStatus.ACTIVE,
        metric="cpu",
        message="CPU yüksek",
        value=95.0,
        threshold=80.0,
        triggered_at=_now(),
    )
    defaults.update(kwargs)
    return Alert(**defaults)


def _nlog(**kwargs) -> NormalizedLog:
    now = _now()
    defaults = dict(
        log_id=_uid(),
        raw_id=_uid(),
        source_type=LogSourceType.SYSLOG,
        observer_hostname="fw01",
        timestamp=now,
        received_at=now,
        severity="warning",
        event_category=LogCategory.AUTHENTICATION,
        event_action="ssh_failure",
        source_ip="10.0.0.1",
        message="SSH login failed",
    )
    defaults.update(kwargs)
    return NormalizedLog(**defaults)


def _corr(**kwargs) -> CorrelatedEvent:
    now = _now()
    defaults = dict(
        corr_id=_uid(),
        rule_id="ssh_brute",
        rule_name="SSH Brute Force",
        event_action="ssh_brute_force_detected",
        severity="critical",
        group_value="10.0.0.5",
        matched_count=10,
        window_seconds=60,
        first_seen=now,
        last_seen=now,
        message="10 SSH failure",
        mitre_techniques=["T1110"],
        mitre_tactics=["credential_access"],
    )
    defaults.update(kwargs)
    return CorrelatedEvent(**defaults)


def _incident(**kwargs) -> Incident:
    defaults = dict(
        incident_id=_uid(),
        title="Test Incident",
        severity="warning",
        created_by="admin",
    )
    defaults.update(kwargs)
    return Incident(**defaults)


# ── Schema ───────────────────────────────────────────────────────────────────

def test_schema_version_nonzero(pg_db):
    version = pg_db.get_schema_version()
    assert version > 0


def test_default_tenant_exists(pg_db):
    tenant = pg_db.get_tenant("default")
    assert tenant is not None
    assert tenant["id"] == "default"


# ── Alerts ───────────────────────────────────────────────────────────────────

def test_save_and_get_alert(pg_db):
    alert = _alert()
    pg_db.save_alert(alert)
    results = pg_db.get_alerts()
    assert any(a.alert_id == alert.alert_id for a in results)


def test_get_alerts_filter_by_status(pg_db):
    active = _alert(status=AlertStatus.ACTIVE)
    resolved = _alert(status=AlertStatus.RESOLVED)
    pg_db.save_alert(active)
    pg_db.save_alert(resolved)

    active_list = pg_db.get_alerts(status="active")
    assert all(a.status == AlertStatus.ACTIVE for a in active_list)
    assert any(a.alert_id == active.alert_id for a in active_list)


def test_save_alert_upsert_on_conflict(pg_db):
    alert = _alert()
    pg_db.save_alert(alert)
    alert.status = AlertStatus.RESOLVED
    pg_db.save_alert(alert)

    results = pg_db.get_alerts()
    match = next(a for a in results if a.alert_id == alert.alert_id)
    assert match.status == AlertStatus.RESOLVED


def test_resolve_all_alerts(pg_db):
    for _ in range(3):
        pg_db.save_alert(_alert(status=AlertStatus.ACTIVE))
    resolved = pg_db.resolve_all_alerts(tenant_id="default")
    assert resolved == 3
    assert pg_db.get_alerts(status="active") == []


# ── Normalized Logs ───────────────────────────────────────────────────────────

def test_save_and_get_normalized_log(pg_db):
    log = _nlog()
    pg_db.save_normalized_log(log)
    results = pg_db.get_normalized_logs()
    assert any(r.log_id == log.log_id for r in results)


def test_get_normalized_logs_filter_by_event_action(pg_db):
    pg_db.save_normalized_log(_nlog(event_action="ssh_failure"))
    pg_db.save_normalized_log(_nlog(event_action="port_scan_attempt"))

    results = pg_db.get_normalized_logs(event_action="ssh_failure")
    assert all(r.event_action == "ssh_failure" for r in results)
    assert len(results) >= 1


def test_save_normalized_log_idempotent(pg_db):
    log = _nlog()
    pg_db.save_normalized_log(log)
    pg_db.save_normalized_log(log)
    results = pg_db.get_normalized_logs(event_action=log.event_action)
    assert sum(1 for r in results if r.log_id == log.log_id) == 1


def test_get_normalized_logs_in_window(pg_db):
    ip = "10.1.2.3"
    for _ in range(3):
        pg_db.save_normalized_log(_nlog(source_ip=ip, event_action="ssh_failure"))
    pg_db.save_normalized_log(_nlog(source_ip="9.9.9.9", event_action="ssh_failure"))

    since = (_now().replace(hour=0, minute=0, second=0)).isoformat()
    results = pg_db.get_normalized_logs_in_window("ssh_failure", "source_ip", ip, since)
    assert all(r.source_ip == ip for r in results)
    assert len(results) == 3


def test_search_logs_fts(pg_db):
    log = _nlog(message="unauthorized access attempt detected brute force")
    pg_db.save_normalized_log(log)
    results = pg_db.search_logs("unauthorized brute")
    assert any(r.log_id == log.log_id for r in results)


def test_search_logs_ip_prefix(pg_db):
    log = _nlog(source_ip="192.168.50.10")
    pg_db.save_normalized_log(log)
    results = pg_db.search_logs("192.168.50")
    assert any(r.log_id == log.log_id for r in results)


def test_search_logs_empty_query_returns_all(pg_db):
    pg_db.save_normalized_log(_nlog())
    results = pg_db.search_logs("")
    assert len(results) >= 1


def test_get_log_volume_returns_list(pg_db):
    pg_db.save_normalized_log(_nlog())
    volume = pg_db.get_log_volume(range="24h")
    assert isinstance(volume, list)
    assert len(volume) >= 1
    assert "t" in volume[0] and "c" in volume[0]


def test_get_related_logs_for_incident(pg_db):
    ip = "10.5.5.5"
    now_iso = _now().isoformat()
    for _ in range(4):
        pg_db.save_normalized_log(_nlog(source_ip=ip))
    results = pg_db.get_related_logs_for_incident(ip, now_iso, window_minutes=60)
    assert all(r.source_ip == ip for r in results)
    assert len(results) == 4


def test_update_log_hostnames(pg_db):
    log = _nlog()
    pg_db.save_normalized_log(log)
    ok = pg_db.update_log_hostnames(log.log_id, "src-host.local", "dst-host.local")
    assert ok is True

    results = pg_db.get_normalized_logs(event_action=log.event_action)
    match = next(r for r in results if r.log_id == log.log_id)
    assert match.source_hostname == "src-host.local"
    assert match.destination_hostname == "dst-host.local"


# ── Correlated Events ─────────────────────────────────────────────────────────

def test_save_and_get_correlated_event(pg_db):
    ce = _corr()
    saved = pg_db.save_correlated_event(ce)
    assert saved is True

    results = pg_db.get_correlated_events()
    assert any(r.corr_id == ce.corr_id for r in results)


def test_correlated_event_deduplication_within_window(pg_db):
    ce = _corr(window_seconds=3600)
    pg_db.save_correlated_event(ce)
    duplicate = _corr(rule_id=ce.rule_id, group_value=ce.group_value, window_seconds=3600)
    saved = pg_db.save_correlated_event(duplicate)
    assert saved is False


def test_get_correlated_event_by_id(pg_db):
    ce = _corr()
    pg_db.save_correlated_event(ce)
    result = pg_db.get_correlated_event_by_id(ce.corr_id)
    assert result is not None
    assert result.corr_id == ce.corr_id
    assert result.mitre_techniques == ["T1110"]


def test_count_correlated_events_since(pg_db):
    pg_db.save_correlated_event(_corr(severity="critical", group_value="10.0.0.10"))
    pg_db.save_correlated_event(_corr(severity="info",     group_value="10.0.0.11"))
    counts = pg_db.count_correlated_events_since(hours=24)
    assert counts["total"] >= 2
    assert counts["high_plus"] >= 1


# ── Attack Chain State ────────────────────────────────────────────────────────

def test_save_and_get_chain_stage(pg_db):
    ip = "10.0.0.99"
    pg_db.save_chain_stage(ip, "RECON", _now())
    pg_db.save_chain_stage(ip, "WEAPONIZE", _now())
    stages = pg_db.get_active_chain_stages(window_seconds=3600)
    assert ip in stages
    assert "RECON" in stages[ip]
    assert "WEAPONIZE" in stages[ip]


def test_purge_old_chain_stages(pg_db):
    from datetime import timedelta
    old_time = _now() - timedelta(hours=2)
    pg_db.save_chain_stage("10.0.0.100", "RECON", old_time)
    pg_db.purge_old_chain_stages(window_seconds=3600)
    stages = pg_db.get_active_chain_stages(window_seconds=3600)
    assert "10.0.0.100" not in stages


# ── Incidents ─────────────────────────────────────────────────────────────────

def test_create_and_get_incident(pg_db):
    inc = _incident()
    pg_db.create_incident(inc)
    result = pg_db.get_incident(inc.incident_id)
    assert result is not None
    assert result["title"] == inc.title
    assert result["severity"] == inc.severity
    assert result["status"] == "open"


def test_update_incident_status(pg_db):
    inc = _incident()
    pg_db.create_incident(inc)
    ok = pg_db.update_incident(inc.incident_id, status="investigating")
    assert ok is True
    result = pg_db.get_incident(inc.incident_id)
    assert result["status"] == "investigating"


def test_update_incident_resolve_sets_resolved_at(pg_db):
    inc = _incident()
    pg_db.create_incident(inc)
    pg_db.update_incident(inc.incident_id, status="resolved", closure_note="kapatıldı")
    result = pg_db.get_incident(inc.incident_id)
    assert result["status"] == "resolved"
    assert result["resolved_at"] is not None
    assert result["closure_note"] == "kapatıldı"


def test_escalate_incident_severity(pg_db):
    inc = _incident(severity="warning")
    pg_db.create_incident(inc)
    ok = pg_db.escalate_incident_severity(inc.incident_id, "critical")
    assert ok is True
    result = pg_db.get_incident(inc.incident_id)
    assert result["severity"] == "critical"


def test_escalate_incident_severity_no_downgrade(pg_db):
    inc = _incident(severity="critical")
    pg_db.create_incident(inc)
    ok = pg_db.escalate_incident_severity(inc.incident_id, "warning")
    assert ok is False


def test_find_open_incident_for_rule(pg_db):
    inc = _incident(rule_id="rule_ssh", group_value="10.0.0.1")
    pg_db.create_incident(inc)
    found = pg_db.find_open_incident_for_rule("rule_ssh", "10.0.0.1")
    assert found == inc.incident_id


def test_count_incidents(pg_db):
    pg_db.create_incident(_incident(status=IncidentStatus.OPEN))
    pg_db.create_incident(_incident(status=IncidentStatus.OPEN))
    assert pg_db.count_incidents(status="open") >= 2


def test_resolve_all_incidents(pg_db):
    pg_db.create_incident(_incident())
    pg_db.create_incident(_incident())
    resolved = pg_db.resolve_all_incidents(tenant_id="default")
    assert resolved >= 2
    assert pg_db.count_incidents(status="open") == 0


def test_add_and_get_incident_events(pg_db):
    inc = _incident()
    pg_db.create_incident(inc)
    pg_db.add_incident_event(
        inc.incident_id, _uid(), "ssh_failure", "warning",
        "Login failed from 10.0.0.1", _now().isoformat(),
    )
    events = pg_db.get_incident_events(inc.incident_id)
    assert len(events) == 1
    assert events[0]["event_action"] == "ssh_failure"


def test_delete_incident(pg_db):
    inc = _incident()
    pg_db.create_incident(inc)
    ok = pg_db.delete_incident(inc.incident_id)
    assert ok is True
    assert pg_db.get_incident(inc.incident_id) is None


# ── Devices ───────────────────────────────────────────────────────────────────

def test_save_and_get_device(pg_db):
    pg_db.save_device("dev-1", "Router A", "router", ip="10.0.0.1")
    device = pg_db.get_device("dev-1")
    assert device is not None
    assert device["name"] == "Router A"
    assert device["ip"] == "10.0.0.1"


def test_save_device_upsert(pg_db):
    pg_db.save_device("dev-2", "Switch B", "switch", ip="10.0.0.2")
    pg_db.save_device("dev-2", "Switch B Updated", "switch", ip="10.0.0.2")
    device = pg_db.get_device("dev-2")
    assert device["name"] == "Switch B Updated"


def test_remove_device(pg_db):
    pg_db.save_device("dev-3", "Server C", "server")
    ok = pg_db.remove_device("dev-3")
    assert ok is True
    assert pg_db.get_device("dev-3") is None


def test_get_devices_filter_by_type(pg_db):
    pg_db.save_device("dev-r1", "Router 1", "router")
    pg_db.save_device("dev-s1", "Switch 1", "switch")
    routers = pg_db.get_devices(device_type="router")
    assert all(d["type"] == "router" for d in routers)


# ── API Keys ──────────────────────────────────────────────────────────────────

def test_save_and_get_api_key(pg_db):
    pg_db.save_api_key("agent-99", "hashed-secret")
    key = pg_db.get_api_key("agent-99")
    assert key == "hashed-secret"


def test_get_all_api_keys(pg_db):
    pg_db.save_api_key("agent-a", "key-a")
    pg_db.save_api_key("agent-b", "key-b")
    keys = pg_db.get_all_api_keys()
    assert keys["agent-a"] == "key-a"
    assert keys["agent-b"] == "key-b"


def test_delete_api_key(pg_db):
    pg_db.save_api_key("agent-del", "to-delete")
    pg_db.delete_api_key("agent-del")
    assert pg_db.get_api_key("agent-del") is None


# ── Audit Log ─────────────────────────────────────────────────────────────────

def test_save_and_get_audit_event(pg_db):
    pg_db.save_audit_event("admin", "login", "auth", "success", "10.0.0.1")
    log = pg_db.get_audit_log(limit=10)
    assert len(log) >= 1
    assert any(e["actor"] == "admin" for e in log)


def test_get_audit_log_filter_by_actor(pg_db):
    pg_db.save_audit_event("alice", "update", "device", "dev-1")
    pg_db.save_audit_event("bob", "delete", "incident", "inc-1")
    log = pg_db.get_audit_log(actor="alice")
    assert all(e["actor"] == "alice" for e in log)


# ── Tenants ───────────────────────────────────────────────────────────────────

def test_create_and_get_tenant(pg_db):
    ok = pg_db.create_tenant("corp-a", "Corp A")
    assert ok is True
    tenant = pg_db.get_tenant("corp-a")
    assert tenant["name"] == "Corp A"


def test_create_tenant_duplicate_returns_false(pg_db):
    pg_db.create_tenant("corp-b", "Corp B")
    ok = pg_db.create_tenant("corp-b", "Corp B Again")
    assert ok is False


def test_update_tenant(pg_db):
    pg_db.create_tenant("corp-c", "Corp C")
    ok = pg_db.update_tenant("corp-c", name="Corp C Renamed")
    assert ok is True
    assert pg_db.get_tenant("corp-c")["name"] == "Corp C Renamed"


def test_delete_tenant(pg_db):
    pg_db.create_tenant("corp-del", "Corp Del")
    ok = pg_db.delete_tenant("corp-del")
    assert ok is True
    assert pg_db.get_tenant("corp-del") is None


def test_delete_default_tenant_is_blocked(pg_db):
    ok = pg_db.delete_tenant("default")
    assert ok is False


# ── Threat Intel Cache ────────────────────────────────────────────────────────

def test_save_and_get_threat_intel(pg_db):
    pg_db.save_threat_intel("1.2.3.4", 85, 42, "TR", "Bad ISP")
    result = pg_db.get_threat_intel("1.2.3.4")
    assert result is not None
    assert result["score"] == 85
    assert result["country_code"] == "TR"


def test_threat_intel_upsert(pg_db):
    pg_db.save_threat_intel("5.6.7.8", 30, 5, "DE", "ISP DE")
    pg_db.save_threat_intel("5.6.7.8", 95, 200, "CN", "ISP CN")
    result = pg_db.get_threat_intel("5.6.7.8")
    assert result["score"] == 95


def test_get_threat_intel_unknown_ip(pg_db):
    assert pg_db.get_threat_intel("255.255.255.255") is None


# ── Token Blacklist ───────────────────────────────────────────────────────────

def test_blacklist_and_check_token(pg_db):
    jti = _uid()
    from datetime import timedelta
    expires = (_now() + timedelta(hours=1)).isoformat()
    pg_db.blacklist_token(jti, expires)
    assert pg_db.is_token_blacklisted(jti) is True


def test_non_blacklisted_token(pg_db):
    assert pg_db.is_token_blacklisted(_uid()) is False


def test_cleanup_expired_blacklist(pg_db):
    from datetime import timedelta
    jti = _uid()
    expired = (_now() - timedelta(hours=1)).isoformat()
    pg_db.blacklist_token(jti, expired)
    removed = pg_db.cleanup_expired_blacklist()
    assert removed >= 1
    assert pg_db.is_token_blacklisted(jti) is False


# ── SNMP Devices ──────────────────────────────────────────────────────────────

def test_add_and_get_snmp_device(pg_db):
    ok = pg_db.add_snmp_device("10.0.0.10", community="public", label="VyOS")
    assert ok is True
    devices = pg_db.get_snmp_devices()
    assert any(d["host"] == "10.0.0.10" for d in devices)


def test_add_snmp_device_duplicate_returns_false(pg_db):
    pg_db.add_snmp_device("10.0.0.11")
    ok = pg_db.add_snmp_device("10.0.0.11")
    assert ok is False


def test_remove_snmp_device(pg_db):
    pg_db.add_snmp_device("10.0.0.12")
    ok = pg_db.remove_snmp_device("10.0.0.12")
    assert ok is True
    assert not any(d["host"] == "10.0.0.12" for d in pg_db.get_snmp_devices())


# ── Asset Baselines ───────────────────────────────────────────────────────────

def test_upsert_and_get_asset_baseline(pg_db):
    now_iso = _now().isoformat()
    pg_db.upsert_asset_baseline(
        source_ip="10.1.1.1",
        tenant_id="default",
        first_seen_at=now_iso,
        last_seen_at=now_iso,
        avg_events_per_hour=5.0,
        typical_ports=[22, 80],
        typical_destinations=["8.8.8.8"],
        typical_event_actions=["ssh_success"],
        sample_hours=24,
    )
    result = pg_db.get_asset_baseline("10.1.1.1")
    assert result is not None
    assert result["avg_events_per_hour"] == 5.0
    assert 22 in result["typical_ports"]


def test_upsert_asset_baseline_updates_on_conflict(pg_db):
    now_iso = _now().isoformat()
    pg_db.upsert_asset_baseline("10.1.1.2", "default", now_iso, now_iso, 2.0, [], [], [], 10)
    pg_db.upsert_asset_baseline("10.1.1.2", "default", now_iso, now_iso, 7.5, [443], [], [], 20)
    result = pg_db.get_asset_baseline("10.1.1.2")
    assert result["avg_events_per_hour"] == 7.5
    assert result["sample_hours"] == 20


# ── DB Users ──────────────────────────────────────────────────────────────────

def test_create_and_get_db_user(pg_db):
    ok = pg_db.create_db_user("testuser", "hash123", "viewer", "default")
    assert ok is True
    user = pg_db.get_db_user("testuser")
    assert user is not None
    assert user["role"] == "viewer"


def test_update_db_user_password(pg_db):
    pg_db.create_db_user("user2", "oldhash", "viewer", "default")
    ok = pg_db.update_db_user_password("user2", "newhash")
    assert ok is True


def test_delete_db_user(pg_db):
    pg_db.create_db_user("user3", "hash", "viewer", "default")
    ok = pg_db.delete_db_user("user3")
    assert ok is True
    assert pg_db.get_db_user("user3") is None


# ── Topology ──────────────────────────────────────────────────────────────────

def test_upsert_topology_node_and_edge(pg_db):
    pg_db.upsert_topology_node("node-1", "Router", ip="10.0.0.1", device_type="router")
    pg_db.upsert_topology_node("node-2", "Switch", ip="10.0.0.2", device_type="switch")
    pg_db.upsert_topology_edge("node-1", "node-2")
    graph = pg_db.get_topology_graph()
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 1


def test_clear_topology(pg_db):
    pg_db.upsert_topology_node("n1", "Node1")
    pg_db.upsert_topology_node("n2", "Node2")
    pg_db.upsert_topology_edge("n1", "n2")
    pg_db.clear_topology()
    graph = pg_db.get_topology_graph()
    assert graph["nodes"] == []
    assert graph["edges"] == []


# ── SNMP Poll History ─────────────────────────────────────────────────────────

def test_upsert_snmp_poll(pg_db):
    pg_db.upsert_snmp_poll("10.0.0.1", "1", "eth0", 1000, 2000)
    result = pg_db.get_snmp_poll("10.0.0.1", "1")
    assert result is not None
    assert result["hc_in"] == 1000
    assert result["if_name"] == "eth0"


def test_upsert_snmp_poll_updates_on_conflict(pg_db):
    pg_db.upsert_snmp_poll("10.0.0.2", "1", "eth0", 500, 600)
    pg_db.upsert_snmp_poll("10.0.0.2", "1", "eth0", 1500, 2000)
    result = pg_db.get_snmp_poll("10.0.0.2", "1")
    assert result["hc_in"] == 1500


# ── False Positive Rules ──────────────────────────────────────────────────────

def test_create_and_get_fp_rule(pg_db):
    now_iso = _now().isoformat()
    pg_db.create_fp_rule(
        fp_rule_id=_uid(),
        event_action="ssh_failure",
        source_ip="10.0.0.1",
        destination_ip=None,
        destination_port=None,
        observer_hostname=None,
        tenant_id="default",
        reason="Authorized scanner",
        created_by="admin",
        created_at=now_iso,
        expires_at=None,
    )
    rules = pg_db.get_active_fp_rules(tenant_id="default")
    assert len(rules) >= 1
    assert any(r["source_ip"] == "10.0.0.1" for r in rules)


def test_deactivate_fp_rule(pg_db):
    now_iso = _now().isoformat()
    rule_id = _uid()
    pg_db.create_fp_rule(rule_id, "port_scan_attempt", "10.0.0.2", None, None, None,
                          "default", "Test", "admin", now_iso, None)
    ok = pg_db.deactivate_fp_rule(rule_id, tenant_id="default")
    assert ok is True
    active = pg_db.get_active_fp_rules(tenant_id="default")
    assert not any(r["fp_rule_id"] == rule_id for r in active)


# ── Sites ─────────────────────────────────────────────────────────────────────

def test_create_and_get_site(pg_db):
    ok = pg_db.create_site("site-1", "default", "Istanbul Office", location="Istanbul", tz="Europe/Istanbul")
    assert ok is True
    site = pg_db.get_site("site-1")
    assert site is not None
    assert site["tz"] == "Europe/Istanbul"


def test_delete_site(pg_db):
    pg_db.create_site("site-del", "default", "To Delete")
    ok = pg_db.delete_site("site-del")
    assert ok is True
    assert pg_db.get_site("site-del") is None


# ── Service Checks ────────────────────────────────────────────────────────────

def test_save_and_get_service_check(pg_db):
    pg_db.save_device("svc-dev", "Web Server", "server", ip="10.0.0.20")
    pg_db.save_service_check("svc-dev", "http", "http://10.0.0.20", "ok", rtt_ms=12.5, port=80)
    checks = pg_db.get_service_checks(device_id="svc-dev")
    assert len(checks) == 1
    assert checks[0]["rtt_ms"] == 12.5


# ── P1: save_batch bulk INSERT ────────────────────────────────────────────────

def test_save_batch_inserts_all_logs(pg_db):
    logs = [_nlog(event_action="port_scan_attempt") for _ in range(3)]
    pg_db.save_batch(logs)
    results = pg_db.get_normalized_logs(event_action="port_scan_attempt")
    inserted_ids = {r.log_id for r in results}
    for log in logs:
        assert log.log_id in inserted_ids


def test_save_batch_all_logs_persisted_in_one_call(pg_db):
    action = "save_batch_one_call_test"
    logs = [_nlog(event_action=action) for _ in range(5)]
    pg_db.save_batch(logs)
    results = pg_db.get_normalized_logs(event_action=action)
    assert len(results) == 5


def test_save_batch_empty_is_noop(pg_db):
    before = len(pg_db.get_normalized_logs())
    pg_db.save_batch([])
    after = len(pg_db.get_normalized_logs())
    assert before == after


def test_save_batch_idempotent_on_duplicate(pg_db):
    log = _nlog(event_action="batch_dup_test")
    pg_db.save_batch([log, log])
    results = pg_db.get_normalized_logs(event_action="batch_dup_test")
    assert sum(1 for r in results if r.log_id == log.log_id) == 1


# ── P3: query_correlated_log_groups → received_at filtresi ───────────────────

def test_query_correlated_log_groups_uses_received_at():
    """query_correlated_log_groups metodunun kaynak kodunun received_at kullandığını doğrula."""
    import inspect
    from server.database import DatabaseManager
    source = inspect.getsource(DatabaseManager.query_correlated_log_groups)
    assert "received_at >=" in source
    assert "timestamp >=" not in source


# ── P8: upsert_kev_entries bulk executemany ───────────────────────────────────

def test_upsert_kev_entries_bulk_returns_new_ids(pg_db):
    entries = [
        {
            "cve_id": f"CVE-2024-{9000 + i}",
            "vendor_project": "Vendor",
            "product": "Product",
            "vulnerability_name": f"Test Vuln {i}",
            "date_added": "2024-01-01",
            "due_date": "2024-02-01",
            "description": "desc",
            "required_action": "patch",
        }
        for i in range(10)
    ]
    new_ids = pg_db.upsert_kev_entries(entries)
    assert len(new_ids) == 10
    assert all(e["cve_id"] in new_ids for e in entries)


def test_upsert_kev_entries_skips_existing(pg_db):
    entry = {
        "cve_id": "CVE-2024-EXISTING-BULK",
        "vendor_project": "V",
        "product": "P",
        "vulnerability_name": "Existing",
        "date_added": "2024-01-01",
        "due_date": None,
        "description": "",
        "required_action": "",
    }
    first = pg_db.upsert_kev_entries([entry])
    assert len(first) == 1

    second = pg_db.upsert_kev_entries([entry])
    assert len(second) == 0


def test_upsert_kev_entries_100_items_all_inserted(pg_db):
    entries = [
        {
            "cve_id": f"CVE-2024-MASS-{i:04d}",
            "vendor_project": "MassV",
            "product": "MassP",
            "vulnerability_name": f"Mass Vuln {i}",
            "date_added": "2024-01-01",
            "due_date": None,
            "description": "",
            "required_action": "",
        }
        for i in range(100)
    ]
    new_ids = pg_db.upsert_kev_entries(entries)
    assert len(new_ids) == 100
    stored = pg_db.get_kev_entries(limit=200)
    stored_ids = {r["cve_id"] for r in stored}
    for e in entries:
        assert e["cve_id"] in stored_ids


# ── P10: get_normalized_logs → offset sayfalama ───────────────────────────────

def test_get_normalized_logs_offset_pagination(pg_db):
    for i in range(10):
        pg_db.save_normalized_log(_nlog(event_action=f"pag_test_{i:03d}"))

    page1 = pg_db.get_normalized_logs(limit=5, offset=0)
    page2 = pg_db.get_normalized_logs(limit=5, offset=5)

    ids1 = {r.log_id for r in page1}
    ids2 = {r.log_id for r in page2}
    assert len(ids1) == 5
    assert len(ids2) == 5
    assert ids1.isdisjoint(ids2)


def test_get_normalized_logs_offset_beyond_end_returns_empty(pg_db):
    pg_db.save_normalized_log(_nlog(event_action="offset_boundary"))
    results = pg_db.get_normalized_logs(event_action="offset_boundary", offset=1000)
    assert results == []
