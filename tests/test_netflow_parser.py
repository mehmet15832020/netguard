"""NetFlow v5 / v9 / IPFIX(v10) / sFlow v5 binary parser testleri."""

import os
import socket
import struct
import time
import pytest
from server.parsers.netflow import (
    parse_v5, parse_v9, detect_and_parse, _v9_templates,
    parse_ipfix, parse_sflow, _ipfix_templates,
)


# ── Yardımcı: sentetik paket oluşturucular ───────────────────────────────────

def make_v5_packet(flows: list[dict]) -> bytes:
    header = struct.pack(
        "!HHIIIIBBH",
        5,            # version
        len(flows),   # count
        60_000,       # sys_uptime ms
        1_714_000_000, # unix_secs
        0,            # unix_nsecs
        1,            # flow_sequence
        0, 0, 0,      # engine_type, engine_id, sampling_interval
    )
    records = b""
    for f in flows:
        src = struct.unpack("!I", socket.inet_aton(f["source_ip"]))[0]
        dst = struct.unpack("!I", socket.inet_aton(f["destination_ip"]))[0]
        records += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBxx",
            src, dst, 0,
            0, 0,
            f.get("pkts", 10),
            f.get("bytes", 1000),
            59_000, 60_000,
            f.get("source_port", 12345),
            f.get("destination_port", 80),
            0,
            f.get("tcp_flags", 0x18),
            f.get("proto", 6),
            0,
            0, 0,
            0, 0,
        )
    return header + records


def make_v9_packet_with_template(flows: list[dict]) -> bytes:
    """Tek template + tek data flowset içeren minimal v9 paketi."""
    source_id   = 1
    template_id = 256

    # Field definitions: (type_id, length)
    fields = [
        (8,  4),  # IPV4_SRC_ADDR
        (12, 4),  # IPV4_DST_ADDR
        (7,  2),  # L4_SRC_PORT
        (11, 2),  # L4_DST_PORT
        (4,  1),  # PROTOCOL
        (2,  4),  # IN_PKTS
        (1,  4),  # IN_BYTES
    ]
    record_size = sum(flen for _, flen in fields)

    # Template FlowSet
    tpl_body = struct.pack("!HH", template_id, len(fields))
    for ftype, flen in fields:
        tpl_body += struct.pack("!HH", ftype, flen)
    tpl_length = 4 + len(tpl_body)
    template_flowset = struct.pack("!HH", 0, tpl_length) + tpl_body

    # Data FlowSet
    data_body = b""
    for f in flows:
        data_body += socket.inet_aton(f["source_ip"])
        data_body += socket.inet_aton(f["destination_ip"])
        data_body += struct.pack("!H", f.get("source_port", 12345))
        data_body += struct.pack("!H", f.get("destination_port", 80))
        data_body += struct.pack("!B", f.get("proto", 6))
        data_body += struct.pack("!I", f.get("pkts", 10))
        data_body += struct.pack("!I", f.get("bytes", 1000))

    # Pad to 4-byte boundary
    pad = (4 - len(data_body) % 4) % 4
    data_body += b"\x00" * pad
    data_length = 4 + len(data_body)
    data_flowset = struct.pack("!HH", template_id, data_length) + data_body

    # v9 header: version(2) count(2) uptime(4) secs(4) seq(4) src_id(4) = 20
    count = 2  # template flowset + data flowset
    header = struct.pack("!HHIIII", 9, count, 60_000, 1_714_000_000, 1, source_id)

    return header + template_flowset + data_flowset


# ── NetFlow v5 testleri ──────────────────────────────────────────────────────

class TestNetFlowV5:
    def test_single_tcp_flow(self):
        pkt = make_v5_packet([{"source_ip": "1.2.3.4", "destination_ip": "5.6.7.8", "proto": 6}])
        logs = parse_v5(pkt, "router1")
        assert len(logs) == 1
        log = logs[0]
        assert log.source_ip == "1.2.3.4"
        assert log.destination_ip == "5.6.7.8"
        assert log.network_protocol == "tcp"

    def test_multiple_flows(self):
        flows = [
            {"source_ip": "10.0.0.1", "destination_ip": "8.8.8.8", "proto": 17, "destination_port": 53},
            {"source_ip": "10.0.0.2", "destination_ip": "1.1.1.1", "proto": 6,  "destination_port": 443},
        ]
        logs = parse_v5(make_v5_packet(flows), "router1")
        assert len(logs) == 2

    def test_udp_protocol_mapped(self):
        pkt = make_v5_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "proto": 17}])
        log = parse_v5(pkt, "r1")[0]
        assert log.network_protocol == "udp"

    def test_icmp_protocol_mapped(self):
        pkt = make_v5_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "proto": 1}])
        log = parse_v5(pkt, "r1")[0]
        assert log.network_protocol == "icmp"

    def test_ports_extracted(self):
        pkt = make_v5_packet([{
            "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
            "source_port": 54321, "destination_port": 443, "proto": 6,
        }])
        log = parse_v5(pkt, "r1")[0]
        assert log.source_port == 54321
        assert log.destination_port == 443

    def test_suspicious_port_is_warning(self):
        pkt = make_v5_packet([{
            "source_ip": "1.1.1.1", "destination_ip": "192.168.1.1",
            "destination_port": 22, "proto": 6,
        }])
        log = parse_v5(pkt, "r1")[0]
        assert log.severity == "warning"

    def test_normal_port_is_info(self):
        pkt = make_v5_packet([{
            "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
            "destination_port": 80, "proto": 6,
        }])
        log = parse_v5(pkt, "r1")[0]
        assert log.severity == "info"

    def test_source_type_netflow(self):
        pkt = make_v5_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        log = parse_v5(pkt, "r1")[0]
        assert log.source_type == "netflow"

    def test_extra_contains_version(self):
        pkt = make_v5_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        log = parse_v5(pkt, "r1")[0]
        assert log.extra["version"] == 5

    def test_packets_and_bytes_in_extra(self):
        pkt = make_v5_packet([{
            "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
            "pkts": 42, "bytes": 9999,
        }])
        log = parse_v5(pkt, "r1")[0]
        assert log.extra["packets"] == 42
        assert log.extra["bytes"] == 9999

    def test_wrong_version_returns_empty(self):
        bad = struct.pack("!H", 7) + b"\x00" * 22
        assert parse_v5(bad, "r") == []

    def test_too_short_returns_empty(self):
        assert parse_v5(b"\x00\x05", "r") == []

    def test_source_host_set(self):
        pkt = make_v5_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        log = parse_v5(pkt, "vyos-router")[0]
        assert log.observer_hostname == "vyos-router"

    def test_event_type(self):
        pkt = make_v5_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        log = parse_v5(pkt, "r1")[0]
        assert log.event_action == "netflow_flow"

    def test_message_contains_ips(self):
        pkt = make_v5_packet([{"source_ip": "10.0.0.1", "destination_ip": "8.8.8.8"}])
        log = parse_v5(pkt, "r1")[0]
        assert "10.0.0.1" in log.message
        assert "8.8.8.8" in log.message


# ── NetFlow v9 testleri ──────────────────────────────────────────────────────

class TestNetFlowV9:
    def setup_method(self):
        _v9_templates.clear()

    def test_single_flow(self):
        pkt = make_v9_packet_with_template([
            {"source_ip": "1.2.3.4", "destination_ip": "5.6.7.8", "proto": 6}
        ])
        logs = parse_v9(pkt, "router1")
        assert len(logs) == 1
        assert logs[0].source_ip == "1.2.3.4"
        assert logs[0].destination_ip == "5.6.7.8"

    def test_protocol_mapped(self):
        pkt = make_v9_packet_with_template([
            {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "proto": 17}
        ])
        logs = parse_v9(pkt, "r1")
        assert logs[0].network_protocol == "udp"

    def test_source_type_netflow(self):
        pkt = make_v9_packet_with_template([
            {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}
        ])
        logs = parse_v9(pkt, "r1")
        assert logs[0].source_type == "netflow"

    def test_extra_version_is_9(self):
        pkt = make_v9_packet_with_template([
            {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}
        ])
        logs = parse_v9(pkt, "r1")
        assert logs[0].extra["version"] == 9

    def test_wrong_version_returns_empty(self):
        bad = struct.pack("!H", 5) + b"\x00" * 18
        assert parse_v9(bad, "r") == []

    def test_too_short_returns_empty(self):
        assert parse_v9(b"\x00\x09", "r") == []


# ── Otomatik tespit ──────────────────────────────────────────────────────────

class TestAutoDetect:
    def setup_method(self):
        _v9_templates.clear()

    def test_detects_v5(self):
        pkt = make_v5_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        logs = detect_and_parse(pkt, "r1")
        assert len(logs) == 1
        assert logs[0].extra["version"] == 5

    def test_detects_v9(self):
        pkt = make_v9_packet_with_template([
            {"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}
        ])
        logs = detect_and_parse(pkt, "r1")
        assert len(logs) == 1
        assert logs[0].extra["version"] == 9

    def test_unknown_version_returns_empty(self):
        bad = struct.pack("!H", 7) + b"\x00" * 20
        assert detect_and_parse(bad, "r") == []

    def test_empty_returns_empty(self):
        assert detect_and_parse(b"", "r") == []

    def test_detects_ipfix(self):
        pkt = make_ipfix_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        logs = detect_and_parse(pkt, "r1")
        assert len(logs) == 1
        assert logs[0].extra["version"] == 10


# ── IPFIX (NetFlow v10) testleri ─────────────────────────────────────────────

def make_ipfix_packet(flows: list[dict], export_time: int = 1_714_000_000) -> bytes:
    """IPFIX v10 paketi: tek template set + tek data set."""
    obs_domain_id = 1
    template_id   = 256

    # IE listesi: (ie_id, ie_len)
    ie_fields = [
        (8,  4),  # sourceIPv4Address
        (12, 4),  # destinationIPv4Address
        (7,  2),  # sourceTransportPort
        (11, 2),  # destinationTransportPort
        (4,  1),  # protocolIdentifier
        (1,  4),  # octetDeltaCount
        (2,  4),  # packetDeltaCount
    ]
    record_size = sum(ie_len for _, ie_len in ie_fields)

    # Template Set (set_id=2)
    tmpl_body = struct.pack("!HH", template_id, len(ie_fields))
    for ie_id, ie_len in ie_fields:
        tmpl_body += struct.pack("!HH", ie_id, ie_len)
    tmpl_set_content_len = 4 + len(tmpl_body)
    pad = (4 - tmpl_set_content_len % 4) % 4
    tmpl_set = struct.pack("!HH", 2, tmpl_set_content_len + pad) + tmpl_body + b"\x00" * pad

    # Data Set (set_id=template_id)
    data_body = b""
    for f in flows:
        data_body += socket.inet_aton(f["source_ip"])
        data_body += socket.inet_aton(f["destination_ip"])
        data_body += struct.pack("!H", f.get("source_port", 12345))
        data_body += struct.pack("!H", f.get("destination_port", 80))
        data_body += struct.pack("!B", f.get("proto", 6))
        data_body += struct.pack("!I", f.get("bytes", 1000))
        data_body += struct.pack("!I", f.get("pkts", 10))
    data_set_content_len = 4 + len(data_body)
    pad = (4 - data_set_content_len % 4) % 4
    data_set = struct.pack("!HH", template_id, data_set_content_len + pad) + data_body + b"\x00" * pad

    total_len = 16 + len(tmpl_set) + len(data_set)
    header = struct.pack("!HHIII", 10, total_len, export_time, 1, obs_domain_id)
    return header + tmpl_set + data_set


class TestIPFIX:
    def setup_method(self):
        _ipfix_templates.clear()

    def test_single_flow(self):
        pkt = make_ipfix_packet([{"source_ip": "1.2.3.4", "destination_ip": "5.6.7.8"}])
        logs = parse_ipfix(pkt, "router1")
        assert len(logs) == 1
        assert logs[0].source_ip == "1.2.3.4"
        assert logs[0].destination_ip == "5.6.7.8"

    def test_source_type_netflow(self):
        pkt = make_ipfix_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        log = parse_ipfix(pkt, "r")[0]
        assert log.source_type == "netflow"

    def test_version_10_in_extra(self):
        pkt = make_ipfix_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        log = parse_ipfix(pkt, "r")[0]
        assert log.extra["version"] == 10

    def test_protocol_mapped(self):
        pkt = make_ipfix_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "proto": 17}])
        log = parse_ipfix(pkt, "r")[0]
        assert log.network_protocol == "udp"

    def test_ports_extracted(self):
        pkt = make_ipfix_packet([{
            "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
            "source_port": 54321, "destination_port": 443,
        }])
        log = parse_ipfix(pkt, "r")[0]
        assert log.source_port == 54321
        assert log.destination_port == 443

    def test_large_flow_is_warning(self):
        large = 60 * 1024 * 1024  # 60 MB
        pkt = make_ipfix_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "bytes": large}])
        log = parse_ipfix(pkt, "r")[0]
        assert log.severity == "warning"
        assert log.event_action == "netflow_large_flow"

    def test_tunneled_protocol_is_warning(self):
        pkt = make_ipfix_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "proto": 47}])  # GRE
        log = parse_ipfix(pkt, "r")[0]
        assert log.severity == "warning"
        assert log.event_action == "netflow_tunneled"

    def test_suspicious_port_is_warning(self):
        pkt = make_ipfix_packet([{
            "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
            "destination_port": 22, "proto": 6,
        }])
        log = parse_ipfix(pkt, "r")[0]
        assert log.severity == "warning"
        assert log.event_action == "netflow_suspicious_port"

    def test_normal_flow_is_info(self):
        pkt = make_ipfix_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        log = parse_ipfix(pkt, "r")[0]
        assert log.severity == "info"
        assert log.event_action == "netflow_flow"

    def test_observer_hostname(self):
        pkt = make_ipfix_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        log = parse_ipfix(pkt, "cisco-switch")[0]
        assert log.observer_hostname == "cisco-switch"

    def test_wrong_version_returns_empty(self):
        bad = struct.pack("!HHIII", 9, 30, 0, 0, 0) + b"\x00" * 14
        assert parse_ipfix(bad, "r") == []

    def test_too_short_returns_empty(self):
        assert parse_ipfix(b"\x00\x0a", "r") == []

    def test_multiple_flows(self):
        flows = [
            {"source_ip": "10.0.0.1", "destination_ip": "8.8.8.8"},
            {"source_ip": "10.0.0.2", "destination_ip": "1.1.1.1"},
        ]
        pkt = make_ipfix_packet(flows)
        logs = parse_ipfix(pkt, "r")
        assert len(logs) == 2

    def test_network_bytes_set(self):
        pkt = make_ipfix_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "bytes": 5000}])
        log = parse_ipfix(pkt, "r")[0]
        assert log.network_bytes == 5000


# ── sFlow v5 testleri ────────────────────────────────────────────────────────

def make_sflow_packet(flows: list[dict], sample_rate: int = 100) -> bytes:
    """sFlow v5 paketi: tek Flow Sample + IPv4 flow record'ları."""
    agent_ip_int = struct.unpack("!I", socket.inet_aton("10.0.0.1"))[0]

    # IPv4 flow record'ları (record_type=3, sampled_ipv4 — RFC 3176)
    records = b""
    for f in flows:
        src_int = struct.unpack("!I", socket.inet_aton(f["source_ip"]))[0]
        dst_int = struct.unpack("!I", socket.inet_aton(f["destination_ip"]))[0]
        ipv4_data = struct.pack(
            "!IIIIIIII",
            64,                          # length (sampled frame size)
            f.get("proto", 6),           # protocol
            src_int,                     # src_ip
            dst_int,                     # dst_ip
            f.get("source_port", 12345), # src_port
            f.get("destination_port", 80), # dst_port
            0,                           # tcp_flags
            0,                           # tos
        )
        records += struct.pack("!II", 3, len(ipv4_data)) + ipv4_data

    # Flow Sample body
    flow_sample = struct.pack(
        "!IIIIIIII",
        1,             # seq
        1,             # src_id
        sample_rate,   # rate
        0,             # pool
        0,             # drops
        1,             # input_if
        2,             # output_if
        len(flows),    # num_records
    ) + records

    # sFlow v5 header
    header = struct.pack(
        "!IIIIIII",
        5,              # version
        1,              # addr_type (IPv4)
        agent_ip_int,   # agent_ip
        0,              # sub_id
        1,              # seq_number
        0,              # uptime
        1,              # num_samples
    )
    sample = struct.pack("!II", 1, len(flow_sample)) + flow_sample
    return header + sample


class TestSFlow:
    def test_basic_flow(self):
        pkt = make_sflow_packet([{"source_ip": "1.2.3.4", "destination_ip": "5.6.7.8"}])
        logs = parse_sflow(pkt, "switch1")
        assert len(logs) == 1
        assert logs[0].source_ip == "1.2.3.4"
        assert logs[0].destination_ip == "5.6.7.8"

    def test_source_type_sflow(self):
        pkt = make_sflow_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        log = parse_sflow(pkt, "sw")[0]
        assert log.source_type == "sflow"

    def test_protocol_mapped(self):
        pkt = make_sflow_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "proto": 17}])
        log = parse_sflow(pkt, "sw")[0]
        assert log.network_protocol == "udp"

    def test_ports_extracted(self):
        pkt = make_sflow_packet([{
            "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
            "source_port": 54321, "destination_port": 443,
        }])
        log = parse_sflow(pkt, "sw")[0]
        assert log.source_port == 54321
        assert log.destination_port == 443

    def test_large_flow_is_warning(self):
        large = 60 * 1024 * 1024
        pkt = make_sflow_packet([{
            "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
            "proto": 6,
        }])
        # Override the frame length via env to keep test deterministic
        os.environ["NETFLOW_LARGE_FLOW_BYTES"] = "1"
        try:
            logs = parse_sflow(pkt, "sw")
        finally:
            del os.environ["NETFLOW_LARGE_FLOW_BYTES"]
        assert logs[0].event_action == "sflow_large_flow"
        assert logs[0].severity == "warning"

    def test_tunneled_protocol_warning(self):
        pkt = make_sflow_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2", "proto": 47}])
        log = parse_sflow(pkt, "sw")[0]
        assert log.event_action == "sflow_tunneled"
        assert log.severity == "warning"

    def test_suspicious_port_warning(self):
        pkt = make_sflow_packet([{
            "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
            "destination_port": 3389, "proto": 6,
        }])
        log = parse_sflow(pkt, "sw")[0]
        assert log.event_action == "sflow_suspicious_port"
        assert log.severity == "warning"

    def test_normal_flow_is_info(self):
        pkt = make_sflow_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        log = parse_sflow(pkt, "sw")[0]
        assert log.event_action == "sflow_flow"
        assert log.severity == "info"

    def test_observer_hostname(self):
        pkt = make_sflow_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}])
        log = parse_sflow(pkt, "arista-sw-01")[0]
        assert log.observer_hostname == "arista-sw-01"

    def test_sample_rate_in_extra(self):
        pkt = make_sflow_packet([{"source_ip": "1.1.1.1", "destination_ip": "2.2.2.2"}], sample_rate=512)
        log = parse_sflow(pkt, "sw")[0]
        assert log.extra["sample_rate"] == 512

    def test_wrong_version_returns_empty(self):
        bad = struct.pack("!IIIIIII", 3, 1, 0, 0, 0, 0, 0) + b"\x00" * 8
        assert parse_sflow(bad, "sw") == []

    def test_too_short_returns_empty(self):
        assert parse_sflow(b"\x00\x00\x00\x05", "sw") == []

    def test_multiple_flows(self):
        flows = [
            {"source_ip": "10.0.0.1", "destination_ip": "8.8.8.8"},
            {"source_ip": "10.0.0.2", "destination_ip": "1.1.1.1"},
            {"source_ip": "10.0.0.3", "destination_ip": "9.9.9.9"},
        ]
        pkt = make_sflow_packet(flows)
        logs = parse_sflow(pkt, "sw")
        assert len(logs) == 3


# ── I7 — IPv6 görünürlük testleri ───────────────────────────────────────────

_GLOBAL_IPV6_SRC = "2606:4700::1111"   # Cloudflare IPv6 DNS — gerçek global unicast
_GLOBAL_IPV6_DST = "2620:fe::fe"       # Hurricane Electric — gerçek global unicast


def _make_v9_ipv6_packet(src_ipv6: str, dst_ipv6: str, src_port=12345, dst_port=80, proto=6) -> bytes:
    """IPv6 adresleri içeren NetFlow v9 paketi (field type 27/28)."""
    source_id   = 1
    template_id = 512

    fields = [
        (27, 16),  # IPV6_SRC_ADDR
        (28, 16),  # IPV6_DST_ADDR
        (7,  2),   # L4_SRC_PORT
        (11, 2),   # L4_DST_PORT
        (4,  1),   # PROTOCOL
        (1,  4),   # IN_BYTES
    ]
    record_size = sum(flen for _, flen in fields)

    tpl_body = struct.pack("!HH", template_id, len(fields))
    for ftype, flen in fields:
        tpl_body += struct.pack("!HH", ftype, flen)
    tpl_length = 4 + len(tpl_body)
    template_fs = struct.pack("!HH", 0, tpl_length) + tpl_body

    # Record: fields must match template exactly (no padding within record)
    data_body  = socket.inet_pton(socket.AF_INET6, src_ipv6)   # 16
    data_body += socket.inet_pton(socket.AF_INET6, dst_ipv6)   # 16
    data_body += struct.pack("!H", src_port)                   # 2
    data_body += struct.pack("!H", dst_port)                   # 2
    data_body += struct.pack("!B", proto)                      # 1
    data_body += struct.pack("!I", 1500)                       # 4  (= 41 bytes total)
    # Pad FlowSet to 4-byte boundary (RFC 3954 §10.3)
    pad = (4 - len(data_body) % 4) % 4
    data_body += b"\x00" * pad

    data_length = 4 + len(data_body)
    data_fs = struct.pack("!HH", template_id, data_length) + data_body

    # v9 header: version(2) count(2) uptime(4) secs(4) seq(4) src_id(4) = 20 bytes
    header = struct.pack("!HHIIII", 9, 2, 60_000, 1_714_000_000, 1, source_id)
    return header + template_fs + data_fs


class TestNetFlowV9IPv6:
    def setup_method(self):
        _v9_templates.clear()

    def test_ipv6_src_dst_parsed(self):
        pkt = _make_v9_ipv6_packet(_GLOBAL_IPV6_SRC, _GLOBAL_IPV6_DST)
        logs = parse_v9(pkt, "router1")
        assert len(logs) == 1
        assert logs[0].source_ip == _GLOBAL_IPV6_SRC
        assert logs[0].destination_ip == _GLOBAL_IPV6_DST

    def test_ipv6_ula_src_parsed(self):
        pkt = _make_v9_ipv6_packet("fd00::cafe", _GLOBAL_IPV6_DST)
        logs = parse_v9(pkt, "r1")
        assert len(logs) == 1
        assert logs[0].source_ip == "fd00::cafe"

    def test_ipv6_flow_has_netflow_source_type(self):
        pkt = _make_v9_ipv6_packet(_GLOBAL_IPV6_SRC, _GLOBAL_IPV6_DST)
        logs = parse_v9(pkt, "r1")
        assert logs[0].source_type == "netflow"

    def test_ipv6_extra_version_is_9(self):
        pkt = _make_v9_ipv6_packet(_GLOBAL_IPV6_SRC, _GLOBAL_IPV6_DST)
        logs = parse_v9(pkt, "r1")
        assert logs[0].extra["version"] == 9


class TestIPv6ActiveResponseProtection:

    def test_ipv6_loopback_is_protected(self):
        from server.routes.active_response import _is_protected
        assert _is_protected("::1") is True

    def test_ipv6_ula_is_protected(self):
        from server.routes.active_response import _is_protected
        assert _is_protected("fd12:3456:789a::1") is True

    def test_ipv6_link_local_is_protected(self):
        from server.routes.active_response import _is_protected
        assert _is_protected("fe80::1") is True

    def test_ipv6_global_unicast_not_protected(self):
        from server.routes.active_response import _is_protected
        assert _is_protected(_GLOBAL_IPV6_SRC) is False

    def test_ipv4_private_still_protected(self):
        from server.routes.active_response import _is_protected
        assert _is_protected("192.168.1.1") is True
        assert _is_protected("10.0.0.1") is True

    def test_attack_chain_ipv6_not_protected(self):
        import ipaddress
        from server.attack_chain import _PROTECTED_NETWORKS
        addr = ipaddress.ip_address(_GLOBAL_IPV6_SRC)
        assert not any(addr in net for net in _PROTECTED_NETWORKS)

    def test_attack_chain_ipv6_loopback_protected(self):
        import ipaddress
        from server.attack_chain import _PROTECTED_NETWORKS
        addr = ipaddress.ip_address("::1")
        assert any(addr in net for net in _PROTECTED_NETWORKS)

    def test_attack_chain_ipv6_ula_protected(self):
        import ipaddress
        from server.attack_chain import _PROTECTED_NETWORKS
        addr = ipaddress.ip_address("fd00::1")
        assert any(addr in net for net in _PROTECTED_NETWORKS)

    def test_attack_chain_ipv6_link_local_protected(self):
        import ipaddress
        from server.attack_chain import _PROTECTED_NETWORKS
        addr = ipaddress.ip_address("fe80::1")
        assert any(addr in net for net in _PROTECTED_NETWORKS)

    def test_threat_intel_ipv6_private_skipped(self):
        from server.threat_intel import _is_private_ip
        assert _is_private_ip("::1") is True
        assert _is_private_ip("fe80::1") is True
        assert _is_private_ip(_GLOBAL_IPV6_SRC) is False
