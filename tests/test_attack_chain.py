"""Attack chain (kill chain) dedektörü testleri."""

from datetime import datetime, timedelta, timezone
from server.attack_chain import AttackChainTracker, CHAIN_WINDOW_SEC


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
        assert result["src_ip"] == "2.2.2.2"
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
        assert result5["src_ip"] == "5.5.5.5"


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
