"""NetFlow v5 ve v9 binary parser testleri."""

import socket
import struct
import pytest
from server.parsers.netflow import parse_v5, parse_v9, detect_and_parse, _v9_templates


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
        src = struct.unpack("!I", socket.inet_aton(f["src_ip"]))[0]
        dst = struct.unpack("!I", socket.inet_aton(f["dst_ip"]))[0]
        records += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBxx",
            src, dst, 0,
            0, 0,
            f.get("pkts", 10),
            f.get("bytes", 1000),
            59_000, 60_000,
            f.get("src_port", 12345),
            f.get("dst_port", 80),
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
        data_body += socket.inet_aton(f["src_ip"])
        data_body += socket.inet_aton(f["dst_ip"])
        data_body += struct.pack("!H", f.get("src_port", 12345))
        data_body += struct.pack("!H", f.get("dst_port", 80))
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
        pkt = make_v5_packet([{"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "proto": 6}])
        logs = parse_v5(pkt, "router1")
        assert len(logs) == 1
        log = logs[0]
        assert log.src_ip == "1.2.3.4"
        assert log.dst_ip == "5.6.7.8"
        assert log.protocol == "tcp"

    def test_multiple_flows(self):
        flows = [
            {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "proto": 17, "dst_port": 53},
            {"src_ip": "10.0.0.2", "dst_ip": "1.1.1.1", "proto": 6,  "dst_port": 443},
        ]
        logs = parse_v5(make_v5_packet(flows), "router1")
        assert len(logs) == 2

    def test_udp_protocol_mapped(self):
        pkt = make_v5_packet([{"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "proto": 17}])
        log = parse_v5(pkt, "r1")[0]
        assert log.protocol == "udp"

    def test_icmp_protocol_mapped(self):
        pkt = make_v5_packet([{"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "proto": 1}])
        log = parse_v5(pkt, "r1")[0]
        assert log.protocol == "icmp"

    def test_ports_extracted(self):
        pkt = make_v5_packet([{
            "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
            "src_port": 54321, "dst_port": 443, "proto": 6,
        }])
        log = parse_v5(pkt, "r1")[0]
        assert log.src_port == 54321
        assert log.dst_port == 443

    def test_suspicious_port_is_warning(self):
        pkt = make_v5_packet([{
            "src_ip": "1.1.1.1", "dst_ip": "192.168.1.1",
            "dst_port": 22, "proto": 6,
        }])
        log = parse_v5(pkt, "r1")[0]
        assert log.severity == "warning"

    def test_normal_port_is_info(self):
        pkt = make_v5_packet([{
            "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
            "dst_port": 80, "proto": 6,
        }])
        log = parse_v5(pkt, "r1")[0]
        assert log.severity == "info"

    def test_source_type_netflow(self):
        pkt = make_v5_packet([{"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}])
        log = parse_v5(pkt, "r1")[0]
        assert log.source_type == "netflow"

    def test_extra_contains_version(self):
        pkt = make_v5_packet([{"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}])
        log = parse_v5(pkt, "r1")[0]
        assert log.extra["version"] == 5

    def test_packets_and_bytes_in_extra(self):
        pkt = make_v5_packet([{
            "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
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
        pkt = make_v5_packet([{"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}])
        log = parse_v5(pkt, "vyos-router")[0]
        assert log.source_host == "vyos-router"

    def test_event_type(self):
        pkt = make_v5_packet([{"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}])
        log = parse_v5(pkt, "r1")[0]
        assert log.event_type == "netflow_flow"

    def test_message_contains_ips(self):
        pkt = make_v5_packet([{"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8"}])
        log = parse_v5(pkt, "r1")[0]
        assert "10.0.0.1" in log.message
        assert "8.8.8.8" in log.message


# ── NetFlow v9 testleri ──────────────────────────────────────────────────────

class TestNetFlowV9:
    def setup_method(self):
        _v9_templates.clear()

    def test_single_flow(self):
        pkt = make_v9_packet_with_template([
            {"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "proto": 6}
        ])
        logs = parse_v9(pkt, "router1")
        assert len(logs) == 1
        assert logs[0].src_ip == "1.2.3.4"
        assert logs[0].dst_ip == "5.6.7.8"

    def test_protocol_mapped(self):
        pkt = make_v9_packet_with_template([
            {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "proto": 17}
        ])
        logs = parse_v9(pkt, "r1")
        assert logs[0].protocol == "udp"

    def test_source_type_netflow(self):
        pkt = make_v9_packet_with_template([
            {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
        ])
        logs = parse_v9(pkt, "r1")
        assert logs[0].source_type == "netflow"

    def test_extra_version_is_9(self):
        pkt = make_v9_packet_with_template([
            {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
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
        pkt = make_v5_packet([{"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}])
        logs = detect_and_parse(pkt, "r1")
        assert len(logs) == 1
        assert logs[0].extra["version"] == 5

    def test_detects_v9(self):
        pkt = make_v9_packet_with_template([
            {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
        ])
        logs = detect_and_parse(pkt, "r1")
        assert len(logs) == 1
        assert logs[0].extra["version"] == 9

    def test_unknown_version_returns_empty(self):
        bad = struct.pack("!H", 7) + b"\x00" * 20
        assert detect_and_parse(bad, "r") == []

    def test_empty_returns_empty(self):
        assert detect_and_parse(b"", "r") == []
