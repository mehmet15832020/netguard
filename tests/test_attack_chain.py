"""Attack chain (kill chain) dedektörü testleri."""

import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest
from server.attack_chain import (
    AttackChainTracker,
    CHAIN_WINDOW_SEC,
    chain_trigger_to_correlated_event,
    _auto_block_full_chain,
)
from server.correlator import Correlator
from shared.models import CorrelatedEvent


def _now():
    return datetime.now(timezone.utc)


class TestStageResolution:
    def test_port_scan_is_recon(self):
        t = AttackChainTracker()
        result = t.record("1.1.1.1", "port_scan_attempt")
        assert result is None  # tek aşama — tetikleme yok

    def test_unknown_event_ignored(self):
        t = AttackChainTracker()
        result = t.record("1.1.1.1", "some_unknown_event_type")
        assert result is None

    def test_no_ip_ignored(self):
        t = AttackChainTracker()
        assert t.record("-", "port_scan_attempt") is None
        assert t.record("", "port_scan_attempt") is None
        assert t.record(None, "port_scan_attempt") is None


class TestPartialChain:
    def test_two_stages_triggers_partial(self):
        t = AttackChainTracker()
        t.record("2.2.2.2", "port_scan_attempt")        # recon
        result = t.record("2.2.2.2", "ssh_failure")     # weaponize
        assert result is not None
        assert result["chain_type"] == "PARTIAL_ATTACK_CHAIN"
        assert result["severity"] == "warning"
        assert result["source_ip"] == "2.2.2.2"
        assert "recon" in result["stages"]
        assert "weaponize" in result["stages"]

    def test_same_stage_twice_no_trigger(self):
        t = AttackChainTracker()
        t.record("3.3.3.3", "port_scan_attempt")
        result = t.record("3.3.3.3", "port_scan_attempt")  # aynı aşama
        assert result is None

    def test_different_ips_independent(self):
        t = AttackChainTracker()
        t.record("4.4.4.4", "port_scan_attempt")
        t.record("5.5.5.5", "ssh_failure")
        # Her IP'nin kendi zinciri var, karışmamalı
        result4 = t.record("4.4.4.4", "port_scan_attempt")
        result5 = t.record("5.5.5.5", "port_scan_attempt")  # 5.5.5.5 için recon + weaponize
        assert result4 is None   # 4.4.4.4 hâlâ tek aşama
        assert result5 is not None
        assert result5["source_ip"] == "5.5.5.5"


class TestFullChain:
    def test_three_stages_triggers_partial(self):
        # FULL_THRESHOLD=4: 3 aşama → PARTIAL (recon gerekli ama sayı yetersiz)
        t = AttackChainTracker()
        t.record("6.6.6.6", "port_scan_attempt")       # recon
        t.record("6.6.6.6", "windows_logon_failure")   # weaponize
        result = t.record("6.6.6.6", "ssh_success")    # access
        assert result is not None
        assert result["chain_type"] == "PARTIAL_ATTACK_CHAIN"

    def test_four_stages_triggers_full(self):
        # FULL_THRESHOLD=4 + recon zorunlu: 4 aşama → FULL_ATTACK_CHAIN
        t = AttackChainTracker()
        t.record("7.7.7.7", "port_scan_attempt")       # recon
        t.record("7.7.7.7", "ssh_failure")              # weaponize
        t.record("7.7.7.7", "ssh_success")              # access
        result = t.record("7.7.7.7", "windows_process_create")  # execute
        assert result is not None
        assert result["chain_type"] == "FULL_ATTACK_CHAIN"
        assert result["severity"] == "critical"
        assert len(result["stages"]) == 4

    def test_four_stages_without_recon_not_full(self):
        # recon olmadan 4 aşama → FULL_ATTACK_CHAIN tetiklenmez
        t = AttackChainTracker()
        t.record("6.1.2.3", "ssh_failure")              # weaponize
        t.record("6.1.2.3", "ssh_success")              # access
        t.record("6.1.2.3", "windows_process_create")   # execute
        result = t.record("6.1.2.3", "ssh_lateral")     # lateral
        assert result is not None
        assert result["chain_type"] == "PARTIAL_ATTACK_CHAIN"

    def test_message_contains_ip_and_stages(self):
        t = AttackChainTracker()
        t.record("8.8.8.8", "port_scan_attempt")
        t.record("8.8.8.8", "brute_force_detected")
        result = t.record("8.8.8.8", "ssh_success")
        assert result is not None
        assert "8.8.8.8" in result["message"]
        assert "aşama" in result["message"].lower() or "SALDIRI" in result["message"]


class TestTimeWindow:
    def test_expired_stage_not_counted(self):
        t = AttackChainTracker()
        past = _now() - timedelta(seconds=CHAIN_WINDOW_SEC + 10)
        t.record("9.9.9.9", "port_scan_attempt", occurred_at=past)  # süresi geçmiş
        result = t.record("9.9.9.9", "ssh_failure")  # yeni event
        # Eski recon pencere dışında — sadece 1 aktif aşama
        assert result is None

    def test_recent_stages_counted(self):
        t = AttackChainTracker()
        recent = _now() - timedelta(seconds=60)
        t.record("10.0.0.1", "port_scan_attempt", occurred_at=recent)
        result = t.record("10.0.0.1", "ssh_failure")
        assert result is not None


class TestPurge:
    def test_purge_removes_old_entries(self):
        t = AttackChainTracker()
        past = _now() - timedelta(seconds=CHAIN_WINDOW_SEC + 60)
        t.record("11.0.0.1", "port_scan_attempt", occurred_at=past)
        t.purge()
        chains = t.get_chains()
        assert "11.0.0.1" not in chains

    def test_purge_keeps_recent(self):
        t = AttackChainTracker()
        t.record("12.0.0.1", "port_scan_attempt")
        t.purge()
        chains = t.get_chains()
        assert "12.0.0.1" in chains


class TestGetChains:
    def test_get_chains_returns_active(self):
        t = AttackChainTracker()
        t.record("13.0.0.1", "port_scan_attempt")
        t.record("13.0.0.1", "ssh_failure")
        chains = t.get_chains()
        assert "13.0.0.1" in chains
        assert "recon" in chains["13.0.0.1"]
        assert "weaponize" in chains["13.0.0.1"]


def _full_trigger(ip="5.6.7.8"):
    return {
        "chain_type": "FULL_ATTACK_CHAIN",
        "severity": "critical",
        "source_ip": ip,
        "stages": ["recon", "weaponize", "access"],
        "stage_labels": ["Keşif", "Erişim Denemeleri", "İlk Erişim"],
        "event_action": "full_attack_chain_detected",
        "message": f"TAM SALDIRI ZİNCİRİ — {ip}",
    }


class TestAutoBlock:
    def test_disabled_by_default_no_block(self, monkeypatch):
        monkeypatch.delenv("AUTO_BLOCK_ON_FULL_CHAIN", raising=False)
        mock_manager = MagicMock()
        with patch("server.active_response.active_response_manager", mock_manager):
            _auto_block_full_chain(_full_trigger())
        mock_manager.block_ip.assert_not_called()

    def test_partial_chain_not_blocked(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        partial = {
            "chain_type": "PARTIAL_ATTACK_CHAIN",
            "severity": "warning",
            "source_ip": "5.6.7.8",
            "stages": ["recon", "weaponize"],
            "stage_labels": [],
            "event_action": "partial_attack_chain_detected",
            "message": "test",
        }
        mock_manager = MagicMock()
        with patch("server.active_response.active_response_manager", mock_manager):
            _auto_block_full_chain(partial)
        mock_manager.block_ip.assert_not_called()

    @pytest.mark.parametrize("protected_ip", [
        "10.0.0.5", "172.16.1.1", "192.168.1.100", "127.0.0.1", "169.254.169.254",
    ])
    def test_protected_networks_not_blocked(self, monkeypatch, protected_ip):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_manager = MagicMock()
        with patch("server.active_response.active_response_manager", mock_manager):
            _auto_block_full_chain(_full_trigger(protected_ip))
        mock_manager.block_ip.assert_not_called()

    def test_protected_cidrs_env_not_blocked(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        monkeypatch.setenv("PROTECTED_CIDRS", "5.6.7.0/24")
        import importlib
        import server.attack_chain as ac
        protected = ac._load_protected_networks()
        mock_manager = MagicMock()
        with patch("server.attack_chain._PROTECTED_NETWORKS", protected):
            with patch("server.active_response.active_response_manager", mock_manager):
                _auto_block_full_chain(_full_trigger("5.6.7.8"))
        mock_manager.block_ip.assert_not_called()

    def test_fp_suppressed_not_blocked(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = "fp-rule-001"
        mock_manager = MagicMock()
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.active_response.active_response_manager", mock_manager):
                _auto_block_full_chain(_full_trigger("5.6.7.8"))
        mock_manager.block_ip.assert_not_called()
        mock_fp.is_suppressed.assert_called_once_with(
            event_action="full_attack_chain_detected",
            source_ip="5.6.7.8",
            tenant_id="default",
        )

    def test_already_blocked_duplicate_skipped(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = True
        mock_manager = MagicMock()
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    _auto_block_full_chain(_full_trigger("5.6.7.8"))
        mock_manager.block_ip.assert_not_called()
        mock_db.is_ip_blocked.assert_called_once_with("5.6.7.8", tenant_id="default")

    def test_public_ip_blocked_when_enabled(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.return_value = {"success": True, "provider": "opnsense"}
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    with patch("server.attack_chain._notify_auto_block_success"):
                        _auto_block_full_chain(_full_trigger("5.6.7.8"))
        mock_manager.block_ip.assert_called_once()
        call_args = mock_manager.block_ip.call_args
        assert call_args[0][0] == "5.6.7.8"
        reason = call_args[0][1]
        assert "FULL_ATTACK_CHAIN" in reason
        assert "recon" in reason
        assert "weaponize" in reason
        assert "access" in reason
        assert call_args[0][2] == "system/kill_chain"

    def test_provider_failure_logged_as_error(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.return_value = {"success": False, "error": "provider down"}
        with caplog.at_level(logging.ERROR, logger="server.attack_chain"):
            with patch("server.fp_manager.fp_manager", mock_fp):
                with patch("server.database.db", mock_db):
                    with patch("server.active_response.active_response_manager", mock_manager):
                        _auto_block_full_chain(_full_trigger("5.6.7.8"))
        assert any("AUTO_BLOCK provider başarısız" in r.message for r in caplog.records)

    def test_block_error_does_not_propagate(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.side_effect = RuntimeError("OPNsense bağlantı hatası")
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    _auto_block_full_chain(_full_trigger("5.6.7.8"))

    def test_chain_trigger_to_correlated_event_calls_auto_block(self):
        trigger = _full_trigger("5.6.7.8")
        with patch("server.attack_chain._auto_block_full_chain") as mock_ab:
            chain_trigger_to_correlated_event(trigger, db_save=False)
        mock_ab.assert_called_once_with(trigger)

    def test_invalid_ip_does_not_raise(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        _auto_block_full_chain(_full_trigger("not-an-ip"))


class TestAutoBlockIntegration:
    """
    Tam pipeline: kill chain kaydı → FULL_ATTACK_CHAIN → chain_trigger_to_correlated_event
    → _auto_block_full_chain çağrısı.
    """

    def test_full_chain_triggers_auto_block(self, monkeypatch):
        # FULL_THRESHOLD=4 + recon zorunlu
        t = AttackChainTracker()
        t.record("5.6.7.8", "port_scan_attempt")        # recon
        t.record("5.6.7.8", "ssh_failure")               # weaponize
        t.record("5.6.7.8", "ssh_success")               # access
        trigger = t.record("5.6.7.8", "windows_process_create")  # execute
        assert trigger is not None
        assert trigger["chain_type"] == "FULL_ATTACK_CHAIN"

        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.return_value = {"success": True, "provider": "opnsense"}
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    chain_trigger_to_correlated_event(trigger, db_save=False)
        mock_manager.block_ip.assert_called_once()
        call_args = mock_manager.block_ip.call_args
        assert call_args[0][0] == "5.6.7.8"
        assert call_args[0][2] == "system/kill_chain"

    def test_partial_chain_does_not_trigger_auto_block(self, monkeypatch):
        t = AttackChainTracker()
        t.record("5.6.7.8", "port_scan_attempt")
        trigger = t.record("5.6.7.8", "ssh_failure")
        assert trigger is not None
        assert trigger["chain_type"] == "PARTIAL_ATTACK_CHAIN"

        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_manager = MagicMock()
        with patch("server.active_response.active_response_manager", mock_manager):
            chain_trigger_to_correlated_event(trigger, db_save=False)
        mock_manager.block_ip.assert_not_called()


def _make_corr_event(group_value: str, group_by_field: str = "source_ip") -> CorrelatedEvent:
    now = datetime.now(timezone.utc)
    return CorrelatedEvent(
        corr_id="test-corr-id",
        rule_id="test-rule",
        rule_name="Test Rule",
        event_action="port_scan_burst",
        severity="high",
        group_by_field=group_by_field,
        group_value=group_value,
        matched_count=5,
        window_seconds=300,
        first_seen=now,
        last_seen=now,
        message="Test event",
    )


class TestU1ManagementIPKillChain:
    """U1 — Management IP'ler kill chain'e girmiyor."""

    def test_management_ip_returns_none(self, monkeypatch):
        monkeypatch.setenv("NETGUARD_MANAGEMENT_IPS", "192.168.203.134")
        import importlib
        import server.attack_chain as ac
        mgmt = frozenset(
            ip.strip()
            for ip in "192.168.203.134".split(",")
            if ip.strip()
        )
        t = AttackChainTracker()
        with patch("server.attack_chain._MANAGEMENT_IPS", mgmt):
            result = t.record("192.168.203.134", "ssh_success")
        assert result is None

    def test_management_ip_full_chain_blocked(self, monkeypatch):
        mgmt = frozenset({"192.168.203.134"})
        t = AttackChainTracker()
        with patch("server.attack_chain._MANAGEMENT_IPS", mgmt):
            t.record("192.168.203.134", "port_scan_attempt")
            t.record("192.168.203.134", "ssh_failure")
            result = t.record("192.168.203.134", "ssh_success")
        assert result is None

    def test_normal_ip_unaffected_by_management_list(self, monkeypatch):
        # FULL_THRESHOLD=4 + recon zorunlu
        mgmt = frozenset({"192.168.203.134"})
        t = AttackChainTracker()
        with patch("server.attack_chain._MANAGEMENT_IPS", mgmt):
            t.record("5.6.7.8", "port_scan_attempt")        # recon
            t.record("5.6.7.8", "ssh_failure")               # weaponize
            t.record("5.6.7.8", "ssh_success")               # access
            result = t.record("5.6.7.8", "windows_process_create")  # execute
        assert result is not None
        assert result["chain_type"] == "FULL_ATTACK_CHAIN"

    def test_empty_management_ips_no_effect(self):
        # FULL_THRESHOLD=4 + recon zorunlu
        mgmt = frozenset()
        t = AttackChainTracker()
        with patch("server.attack_chain._MANAGEMENT_IPS", mgmt):
            t.record("1.2.3.4", "port_scan_attempt")         # recon
            t.record("1.2.3.4", "ssh_failure")                # weaponize
            t.record("1.2.3.4", "ssh_success")                # access
            result = t.record("1.2.3.4", "windows_process_create")  # execute
        assert result is not None
        assert result["chain_type"] == "FULL_ATTACK_CHAIN"


class TestKillChainNamespaceGuard:
    def test_hostname_group_by_skips_kill_chain(self, caplog):
        c = Correlator()
        event = _make_corr_event("WIN-WS", group_by_field="observer_hostname")
        mock_tracker = MagicMock()
        with caplog.at_level(logging.DEBUG, logger="server.correlator"):
            with patch("server.attack_chain.attack_chain_tracker", mock_tracker):
                c._check_attack_chain(event)
        mock_tracker.record.assert_not_called()
        assert any("kill chain skipped" in r.message for r in caplog.records)

    def test_source_ip_group_by_proceeds(self):
        c = Correlator()
        event = _make_corr_event("5.6.7.8", group_by_field="source_ip")
        mock_tracker = MagicMock()
        mock_tracker.record.return_value = None
        with patch("server.attack_chain.attack_chain_tracker", mock_tracker):
            c._check_attack_chain(event)
        mock_tracker.record.assert_called_once_with(
            source_ip="5.6.7.8",
            event_action="port_scan_burst",
        )

    def test_non_ip_value_skips_kill_chain(self, caplog):
        c = Correlator()
        event = _make_corr_event("not-an-ip", group_by_field="source_ip")
        mock_tracker = MagicMock()
        with caplog.at_level(logging.DEBUG, logger="server.correlator"):
            with patch("server.attack_chain.attack_chain_tracker", mock_tracker):
                c._check_attack_chain(event)
        mock_tracker.record.assert_not_called()
        assert any("kill chain skipped" in r.message for r in caplog.records)

    def test_ipv6_address_proceeds(self):
        c = Correlator()
        event = _make_corr_event("2001:db8::1", group_by_field="source_ip")
        mock_tracker = MagicMock()
        mock_tracker.record.return_value = None
        with patch("server.attack_chain.attack_chain_tracker", mock_tracker):
            c._check_attack_chain(event)
        mock_tracker.record.assert_called_once()

    def test_destination_ip_group_by_skips_kill_chain(self, caplog):
        c = Correlator()
        event = _make_corr_event("10.0.0.1", group_by_field="destination_ip")
        mock_tracker = MagicMock()
        with caplog.at_level(logging.DEBUG, logger="server.correlator"):
            with patch("server.attack_chain.attack_chain_tracker", mock_tracker):
                c._check_attack_chain(event)
        mock_tracker.record.assert_not_called()


class TestQ4AutoBlockNotification:
    """Q4 — Auto-block bildiriminde kill chain bağlamı (aşamalar + tetikleyen action)."""

    def test_block_reason_contains_stages(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.return_value = {"success": True, "provider": "opnsense"}
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    with patch("server.attack_chain._notify_auto_block_success"):
                        _auto_block_full_chain(_full_trigger("5.6.7.9"))
        reason = mock_manager.block_ip.call_args[0][1]
        assert "recon" in reason
        assert "weaponize" in reason
        assert "access" in reason

    def test_block_reason_contains_triggering_action(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.return_value = {"success": True, "provider": "opnsense"}
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    with patch("server.attack_chain._notify_auto_block_success"):
                        _auto_block_full_chain(_full_trigger("5.6.7.9"))
        reason = mock_manager.block_ip.call_args[0][1]
        assert "full_attack_chain_detected" in reason

    def test_notify_auto_block_success_called_on_success(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.return_value = {"success": True, "provider": "opnsense"}
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    with patch("server.attack_chain._notify_auto_block_success") as mock_notify:
                        _auto_block_full_chain(_full_trigger("5.6.7.9"))
        mock_notify.assert_called_once()
        call_args = mock_notify.call_args[0]
        assert call_args[0] == "5.6.7.9"
        assert isinstance(call_args[1], list)
        assert "full_attack_chain_detected" in call_args[2]

    def test_notify_auto_block_success_not_called_on_failure(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.return_value = {"success": False, "error": "provider down"}
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    with patch("server.attack_chain._notify_auto_block_success") as mock_notify:
                        _auto_block_full_chain(_full_trigger("5.6.7.9"))
        mock_notify.assert_not_called()

    def test_notify_auto_block_success_email_sent(self):
        from server.attack_chain import _notify_auto_block_success
        from server.notifier import Notifier
        n = Notifier()
        n.email.enabled = True
        sent = []
        n.email.send_custom = lambda subj, body: sent.append((subj, body))
        n.webhook.enabled = False
        with patch("server.notifier.notifier", n):
            _notify_auto_block_success(
                "8.8.8.8",
                ["Keşif", "Erişim Denemeleri", "İlk Erişim"],
                "full_attack_chain_detected",
                "opnsense",
                ttl_hours=4.0,
                offense_count=2,
            )
        assert len(sent) >= 1
        assert "8.8.8.8" in sent[0][0]
        assert "Keşif" in sent[0][1]
        assert "full_attack_chain_detected" in sent[0][1]
        assert "4 saat" in sent[0][1]
        assert "2" in sent[0][1]

    def test_notify_auto_block_success_default_ttl_label(self):
        from server.attack_chain import _notify_auto_block_success
        from server.notifier import Notifier
        n = Notifier()
        n.email.enabled = True
        sent = []
        n.email.send_custom = lambda subj, body: sent.append((subj, body))
        n.webhook.enabled = False
        with patch("server.notifier.notifier", n):
            _notify_auto_block_success("1.2.3.4", ["Keşif"], "port_scan", "vyos")
        assert "varsayılan" in sent[0][1]


class TestAutoBlockR1ThreatIntelGate:
    """R1 — Threat intel eşiği olmadan otomatik blok atlanmalı."""

    def test_low_intel_score_skips_block(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "30")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        with patch("server.threat_intel.lookup", return_value={"composite_score": 10}):
            with patch("server.fp_manager.fp_manager", mock_fp):
                with patch("server.database.db", mock_db):
                    with patch("server.active_response.active_response_manager", mock_manager):
                        _auto_block_full_chain(_full_trigger())
        mock_manager.block_ip.assert_not_called()

    def test_high_intel_score_allows_block(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "30")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.return_value = {"success": True, "provider": "opnsense", "error": ""}
        with patch("server.threat_intel.lookup", return_value={"composite_score": 75}):
            with patch("server.fp_manager.fp_manager", mock_fp):
                with patch("server.database.db", mock_db):
                    with patch("server.active_response.active_response_manager", mock_manager):
                        _auto_block_full_chain(_full_trigger())
        mock_manager.block_ip.assert_called_once()

    def test_zero_score_threshold_skips_intel_check(self, monkeypatch):
        """AUTO_BLOCK_MIN_INTEL_SCORE=0 → threat intel gate devre dışı."""
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.return_value = {"success": True, "provider": "opnsense", "error": ""}
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    _auto_block_full_chain(_full_trigger())
        mock_manager.block_ip.assert_called_once()


class TestAutoBlockR4ActiveSession:
    """R4 — Aktif oturum varsa otomatik blok atlanmalı."""

    def test_active_session_skips_block(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_db.has_active_session.return_value = True
        mock_manager = MagicMock()
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    _auto_block_full_chain(_full_trigger())
        mock_manager.block_ip.assert_not_called()
        mock_db.save_audit_event.assert_called_once()
        detail = mock_db.save_audit_event.call_args[1]["detail"]
        assert "aktif" in detail.lower() or "session" in detail.lower()

    def test_no_active_session_allows_block(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        monkeypatch.setenv("AUTO_BLOCK_MIN_INTEL_SCORE", "0")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_db.has_active_session.return_value = False
        mock_db.has_active_session.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.return_value = {"success": True, "provider": "opnsense", "error": ""}
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    _auto_block_full_chain(_full_trigger())
        mock_manager.block_ip.assert_called_once()

    def test_has_active_session_db_method(self, tmp_db):
        """has_active_session() SQL doğruluğu — DB metodu test."""
        from server.database import db
        from datetime import datetime, timezone
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        import uuid
        log = NormalizedLog(
            log_id=str(uuid.uuid4()),
            raw_id=str(uuid.uuid4()),
            source_type=LogSourceType.AUTH_LOG,
            observer_hostname="server",
            timestamp=datetime.now(timezone.utc),
            severity="info",
            event_category=LogCategory.AUTHENTICATION,
            event_action="ssh_login_success",
            source_ip="10.0.0.50",
            message="SSH login success",
        )
        db.save_normalized_log(log)
        assert db.has_active_session("10.0.0.50", window_seconds=3600) is True
        assert db.has_active_session("10.0.0.99", window_seconds=3600) is False
