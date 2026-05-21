"""Attack chain (kill chain) dedektörü testleri."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest
from server.attack_chain import (
    AttackChainTracker,
    CHAIN_WINDOW_SEC,
    chain_trigger_to_correlated_event,
    _auto_block_full_chain,
)


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
    def test_three_stages_triggers_full(self):
        t = AttackChainTracker()
        t.record("6.6.6.6", "port_scan_attempt")       # recon
        t.record("6.6.6.6", "windows_logon_failure")   # weaponize
        result = t.record("6.6.6.6", "ssh_success")    # access
        assert result is not None
        assert result["chain_type"] == "FULL_ATTACK_CHAIN"
        assert result["severity"] == "critical"
        assert len(result["stages"]) == 3

    def test_four_stages_still_full(self):
        t = AttackChainTracker()
        t.record("7.7.7.7", "port_scan_attempt")
        t.record("7.7.7.7", "ssh_failure")
        t.record("7.7.7.7", "ssh_success")
        result = t.record("7.7.7.7", "windows_process_create")
        assert result["chain_type"] == "FULL_ATTACK_CHAIN"
        assert len(result["stages"]) == 4

    def test_message_contains_ip_and_stages(self):
        t = AttackChainTracker()
        t.record("8.8.8.8", "port_scan_attempt")
        t.record("8.8.8.8", "brute_force_detected")
        result = t.record("8.8.8.8", "ssh_success")
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
        mock_manager = MagicMock()
        with patch("server.active_response.active_response_manager", mock_manager):
            _auto_block_full_chain(_full_trigger(protected_ip))
        mock_manager.block_ip.assert_not_called()

    def test_protected_cidrs_env_not_blocked(self, monkeypatch):
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
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
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
        mock_manager = MagicMock()
        mock_manager.block_ip.return_value = {"success": True, "provider": "opnsense"}
        with patch("server.fp_manager.fp_manager", mock_fp):
            with patch("server.database.db", mock_db):
                with patch("server.active_response.active_response_manager", mock_manager):
                    _auto_block_full_chain(_full_trigger("5.6.7.8"))
        mock_manager.block_ip.assert_called_once_with(
            "5.6.7.8",
            "Otomatik bloklama: FULL_ATTACK_CHAIN (recon, weaponize, access)",
            "system/kill_chain",
            tenant_id="default",
        )

    def test_provider_failure_logged_as_error(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
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
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
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
        _auto_block_full_chain(_full_trigger("not-an-ip"))


class TestAutoBlockIntegration:
    """
    Tam pipeline: kill chain kaydı → FULL_ATTACK_CHAIN → chain_trigger_to_correlated_event
    → _auto_block_full_chain çağrısı.
    """

    def test_full_chain_triggers_auto_block(self, monkeypatch):
        t = AttackChainTracker()
        t.record("5.6.7.8", "port_scan_attempt")
        t.record("5.6.7.8", "ssh_failure")
        trigger = t.record("5.6.7.8", "ssh_success")
        assert trigger is not None
        assert trigger["chain_type"] == "FULL_ATTACK_CHAIN"

        monkeypatch.setenv("AUTO_BLOCK_ON_FULL_CHAIN", "1")
        mock_fp = MagicMock()
        mock_fp.is_suppressed.return_value = None
        mock_db = MagicMock()
        mock_db.is_ip_blocked.return_value = False
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
        mock_manager = MagicMock()
        with patch("server.active_response.active_response_manager", mock_manager):
            chain_trigger_to_correlated_event(trigger, db_save=False)
        mock_manager.block_ip.assert_not_called()
