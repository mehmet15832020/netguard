"""
D1 — NetFlow Sigma kuralları testleri.
Kapsam:
  - NetFlow parser event_action sınıflandırması (large_flow / tunneled / suspicious_port / normal)
  - Sigma kuralı yükleme ve SQL üretimi
  - STAGE_MAP entegrasyonu (kill chain aşama eşleme)
  - Parser + Sigma korelasyon uçtan uca
"""

import struct
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from server.parsers.netflow import (
    _LARGE_FLOW_BYTES,
    _SUSPICIOUS_PORTS,
    _TUNNELED_PROTOCOLS,
    _event_action_for_flow,
    parse_v5,
    parse_v9,
    _v9_templates,
)
from server.attack_chain import _resolve_stage as get_stage, STAGE_MAP
from server.sigma_executor import SigmaExecutor


# ── Yardımcı: NetFlow v5 paketi üret ────────────────────────────────────────

def _make_v5_packet(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "8.8.8.8",
    src_port: int = 12345,
    dst_port: int = 80,
    proto: int = 6,
    pkts: int = 10,
    octets: int = 1000,
    unix_secs: int = 1_700_000_000,
) -> bytes:
    import socket as _sock

    def ip2int(ip: str) -> int:
        return struct.unpack("!I", _sock.inet_aton(ip))[0]

    header = struct.pack(
        "!HHIIIIBBH",
        5,          # version
        1,          # count
        0,          # sys_uptime
        unix_secs,  # unix_secs
        0,          # unix_nsecs
        0,          # flow_sequence
        0,          # engine_type
        0,          # engine_id
        0,          # sampling
    )
    record = struct.pack(
        "!IIIHHIIIIHHBBBBHHBBxx",
        ip2int(src_ip),  # srcaddr
        ip2int(dst_ip),  # dstaddr
        0,               # nexthop
        0,               # input
        0,               # output
        pkts,            # dPkts
        octets,          # dOctets
        0,               # first
        0,               # last
        src_port,        # srcport
        dst_port,        # dstport
        0,               # pad1
        0,               # tcp_flags
        proto,           # prot
        0,               # tos
        0,               # src_as
        0,               # dst_as
        0,               # src_mask
        0,               # dst_mask
    )
    return header + record


# ── TestEventActionClassification ────────────────────────────────────────────

class TestEventActionClassification:
    def test_normal_flow_returns_netflow_flow(self):
        action = _event_action_for_flow(6, 80, 12345, 1000)
        assert action == "netflow_flow"

    def test_large_flow_returns_netflow_large_flow(self):
        big = _LARGE_FLOW_BYTES + 1
        action = _event_action_for_flow(6, 80, 12345, big)
        assert action == "netflow_large_flow"

    def test_large_flow_threshold_exact(self):
        action_at = _event_action_for_flow(6, 80, 12345, _LARGE_FLOW_BYTES)
        action_over = _event_action_for_flow(6, 80, 12345, _LARGE_FLOW_BYTES + 1)
        assert action_at == "netflow_flow"
        assert action_over == "netflow_large_flow"

    def test_gre_tunneled_protocol(self):
        assert 47 in _TUNNELED_PROTOCOLS
        action = _event_action_for_flow(47, 0, 0, 100)
        assert action == "netflow_tunneled"

    def test_esp_tunneled_protocol(self):
        assert 50 in _TUNNELED_PROTOCOLS
        action = _event_action_for_flow(50, 0, 0, 100)
        assert action == "netflow_tunneled"

    def test_ipv6_in_ipv4_tunneled(self):
        assert 41 in _TUNNELED_PROTOCOLS
        action = _event_action_for_flow(41, 0, 0, 100)
        assert action == "netflow_tunneled"

    def test_suspicious_dst_port(self):
        for port in _SUSPICIOUS_PORTS:
            action = _event_action_for_flow(6, port, 12345, 100)
            assert action == "netflow_suspicious_port", f"port {port} suspicious olmalı"

    def test_suspicious_src_port(self):
        action = _event_action_for_flow(6, 80, 4444, 100)
        assert action == "netflow_suspicious_port"

    def test_large_flow_priority_over_suspicious_port(self):
        big = _LARGE_FLOW_BYTES + 1
        action = _event_action_for_flow(6, 22, 12345, big)
        assert action == "netflow_large_flow", "large_flow suspicious_port'tan önce gelir"

    def test_tunnel_priority_over_suspicious_port(self):
        action = _event_action_for_flow(47, 22, 12345, 100)
        assert action == "netflow_tunneled", "tunneled suspicious_port'tan önce gelir"

    def test_large_flow_priority_over_tunnel(self):
        big = _LARGE_FLOW_BYTES + 1
        action = _event_action_for_flow(47, 0, 0, big)
        assert action == "netflow_large_flow", "large_flow tunneled'dan önce gelir"

    def test_icmp_normal_flow(self):
        action = _event_action_for_flow(1, 0, 0, 500)
        assert action == "netflow_flow"

    def test_zero_bytes_not_large(self):
        action = _event_action_for_flow(6, 80, 12345, 0)
        assert action == "netflow_flow"


# ── TestParserEventAction ─────────────────────────────────────────────────────

class TestParserEventAction:
    def test_v5_normal_flow_event_action(self):
        pkt = _make_v5_packet(dst_port=80, octets=500, proto=6)
        logs = parse_v5(pkt, "test-host")
        assert len(logs) == 1
        assert logs[0].event_action == "netflow_flow"

    def test_v5_large_flow_event_action(self):
        big = _LARGE_FLOW_BYTES + 1
        pkt = _make_v5_packet(dst_port=80, octets=big, proto=6)
        logs = parse_v5(pkt, "test-host")
        assert len(logs) == 1
        assert logs[0].event_action == "netflow_large_flow"

    def test_v5_tunneled_protocol_event_action(self):
        pkt = _make_v5_packet(dst_port=0, octets=100, proto=47)
        logs = parse_v5(pkt, "test-host")
        assert len(logs) == 1
        assert logs[0].event_action == "netflow_tunneled"

    def test_v5_suspicious_port_event_action(self):
        pkt = _make_v5_packet(dst_port=3389, octets=100, proto=6)
        logs = parse_v5(pkt, "test-host")
        assert len(logs) == 1
        assert logs[0].event_action == "netflow_suspicious_port"

    def test_v5_network_bytes_populated(self):
        pkt = _make_v5_packet(octets=9999)
        logs = parse_v5(pkt, "test-host")
        assert logs[0].network_bytes == 9999

    def test_v5_large_flow_network_bytes_correct(self):
        big = _LARGE_FLOW_BYTES + 100
        pkt = _make_v5_packet(octets=big)
        logs = parse_v5(pkt, "test-host")
        assert logs[0].network_bytes == big

    def test_large_flow_env_override(self):
        with patch("server.parsers.netflow._LARGE_FLOW_BYTES", 1000):
            action = _event_action_for_flow(6, 80, 12345, 1001)
            assert action == "netflow_large_flow"

            action_under = _event_action_for_flow(6, 80, 12345, 999)
            assert action_under == "netflow_flow"


# ── TestSigmaRulesLoad ────────────────────────────────────────────────────────

class TestSigmaRulesLoad:
    @pytest.fixture(scope="class")
    def executor(self):
        ex = SigmaExecutor()
        ex.load_dir()
        return ex

    def test_netflow_rules_loaded(self, executor):
        netflow_rules = [r for r in executor.rules
                         if "netflow" in r.title.lower()]
        assert len(netflow_rules) == 3, f"3 NetFlow kuralı beklendi, {len(netflow_rules)} yüklendi"

    def test_large_flow_exfil_rule_exists(self, executor):
        rules = [r for r in executor.rules if "Large Flow" in r.title]
        assert len(rules) == 1
        assert rules[0].is_correlation
        assert rules[0].severity == "high"

    def test_suspicious_port_burst_rule_exists(self, executor):
        rules = [r for r in executor.rules if "Suspicious Port" in r.title]
        assert len(rules) == 1
        assert rules[0].is_correlation
        assert rules[0].severity == "high"

    def test_tunnel_burst_rule_exists(self, executor):
        rules = [r for r in executor.rules if "NetFlow Tunnel" in r.title]
        assert len(rules) == 1
        assert rules[0].is_correlation
        assert rules[0].severity == "critical"

    def test_large_flow_rule_groups_by_source_ip(self, executor):
        rule = next(r for r in executor.rules if "Large Flow" in r.title)
        assert "source_ip" in rule.sql

    def test_tunnel_rule_groups_by_destination_ip(self, executor):
        rule = next(r for r in executor.rules if "NetFlow Tunnel" in r.title)
        assert "destination_ip" in rule.sql

    def test_netflow_rules_have_mitre_tags(self, executor):
        netflow_rules = [r for r in executor.rules if "netflow" in r.title.lower()]
        for rule in netflow_rules:
            assert len(rule.tags) > 0, f"{rule.title} MITRE tag yok"

    def test_netflow_rules_have_valid_sql(self, executor):
        netflow_rules = [r for r in executor.rules if "netflow" in r.title.lower()]
        for rule in netflow_rules:
            assert "SELECT" in rule.sql.upper()
            assert "normalized_logs" in rule.sql
            assert "netflow" in rule.sql.lower()


# ── TestStageMap ──────────────────────────────────────────────────────────────

class TestStageMap:
    def test_netflow_large_flow_maps_to_lateral(self):
        assert get_stage("netflow_large_flow") == "lateral"

    def test_netflow_suspicious_port_maps_to_lateral(self):
        assert get_stage("netflow_suspicious_por") == "lateral"

    def test_netflow_tunneled_maps_to_lateral(self):
        assert get_stage("netflow_tunneled") == "lateral"

    def test_netflow_exfil_burst_slug_maps_to_lateral(self):
        assert get_stage("netflow_large_flow_exf") == "lateral"

    def test_netflow_tunnel_burst_slug_maps_to_lateral(self):
        assert get_stage("netflow_tunnel_protoco") == "lateral"

    def test_regular_netflow_flow_has_no_stage(self):
        stage = get_stage("netflow_flow")
        assert stage is None or stage == "recon"
