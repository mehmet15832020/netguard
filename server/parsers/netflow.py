"""
NetGuard — NetFlow v5 / v9 Binary Parser

NetFlow v5: Sabit boyutlu kayıtlar (24 byte header + 48 byte/flow)
NetFlow v9: Template tabanlı — önce template alınır, sonra data parse edilir

Her parse çağrısı list[NormalizedLog] döner (birden fazla akış olabilir).
"""

import logging
import socket
import struct
import uuid
from datetime import datetime, timezone
from typing import Optional

from shared.models import LogCategory, LogSourceType, NormalizedLog

logger = logging.getLogger(__name__)

# ── NetFlow v5 ────────────────────────────────────────────────────────────────

_V5_HEADER  = struct.Struct("!HHIIIIBBH")   # 24 bytes
_V5_RECORD  = struct.Struct("!IIIHHIIIIHHBBBBHHBBxx")  # 48 bytes

_V5_HEADER_SIZE = _V5_HEADER.size   # 24
_V5_RECORD_SIZE = _V5_RECORD.size   # 48

_PROTO_MAP = {
    1: "icmp", 6: "tcp", 17: "udp",
    47: "gre", 50: "esp", 58: "icmpv6", 89: "ospf",
}

_SUSPICIOUS_PORTS = {22, 23, 3389, 445, 135, 5900, 4444, 1337}


def _ip_from_int(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", n))


def _severity_for_flow(proto: str, dst_port: int, src_port: int) -> str:
    if dst_port in _SUSPICIOUS_PORTS or src_port in _SUSPICIOUS_PORTS:
        return "warning"
    return "info"


def _make_log(
    source_host: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    proto_num: int,
    packets: int,
    octets: int,
    unix_secs: int,
    extra: dict,
) -> NormalizedLog:
    proto = _PROTO_MAP.get(proto_num, str(proto_num))
    severity = _severity_for_flow(proto, dst_port, src_port)
    ts = datetime.fromtimestamp(unix_secs, tz=timezone.utc)

    return NormalizedLog(
        log_id      = str(uuid.uuid4()),
        raw_id      = str(uuid.uuid4()),
        source_type = LogSourceType.NETFLOW,
        source_host = source_host,
        timestamp   = ts,
        severity    = severity,
        category    = LogCategory.NETWORK,
        event_type  = "netflow_flow",
        src_ip      = src_ip,
        dst_ip      = dst_ip,
        src_port    = src_port,
        dst_port    = dst_port,
        protocol    = proto,
        message     = (
            f"NetFlow {proto.upper()} "
            f"{src_ip}:{src_port} → {dst_ip}:{dst_port} "
            f"({packets} pkts, {octets} B)"
        ),
        tags        = [proto, f"dst:{dst_port}"],
        extra       = {**extra, "packets": packets, "bytes": octets},
    )


def parse_v5(data: bytes, source_host: str) -> list[NormalizedLog]:
    if len(data) < _V5_HEADER_SIZE:
        return []
    hdr = _V5_HEADER.unpack_from(data, 0)
    version, count = hdr[0], hdr[1]
    if version != 5:
        return []
    unix_secs = hdr[3]

    expected = _V5_HEADER_SIZE + count * _V5_RECORD_SIZE
    if len(data) < expected:
        count = (len(data) - _V5_HEADER_SIZE) // _V5_RECORD_SIZE

    logs = []
    for i in range(count):
        offset = _V5_HEADER_SIZE + i * _V5_RECORD_SIZE
        try:
            r = _V5_RECORD.unpack_from(data, offset)
        except struct.error:
            break
        (srcaddr, dstaddr, _nexthop, _in, _out,
         pkts, octets, _first, _last,
         srcport, dstport, _pad1, tcp_flags, prot, tos,
         src_as, dst_as, _smask, _dmask) = r

        logs.append(_make_log(
            source_host = source_host,
            src_ip      = _ip_from_int(srcaddr),
            dst_ip      = _ip_from_int(dstaddr),
            src_port    = srcport,
            dst_port    = dstport,
            proto_num   = prot,
            packets     = pkts,
            octets      = octets,
            unix_secs   = unix_secs,
            extra       = {
                "version":   5,
                "tcp_flags": tcp_flags,
                "tos":       tos,
                "src_as":    src_as,
                "dst_as":    dst_as,
            },
        ))
    return logs


# ── NetFlow v9 ────────────────────────────────────────────────────────────────

_V9_HEADER = struct.Struct("!HHIII")  # 20 bytes: version, count, uptime, secs, seq, src_id
# Actually v9 header: version(2), count(2), sys_uptime(4), unix_secs(4), package_sequence(4), source_id(4) = 20
_V9_HEADER = struct.Struct("!HHIIII")  # 24 bytes — wait: 2+2+4+4+4+4=20, so 5 I's is wrong
# version(H=2) + count(H=2) + sys_uptime(I=4) + unix_secs(I=4) + pkg_seq(I=4) + src_id(I=4) = 20
_V9_HEADER = struct.Struct("!HHIIII")   # 2+2+4+4+4+4 = 20 bytes ✓

_V9_FLOWSET_HDR = struct.Struct("!HH")  # flowset_id(2) + length(2)

# Field type → (name, struct_fmt)
_V9_FIELD_TYPES: dict[int, tuple[str, str]] = {
    1:  ("in_bytes",    "!I"),
    2:  ("in_pkts",     "!I"),
    4:  ("protocol",    "!B"),
    5:  ("tos",         "!B"),
    6:  ("tcp_flags",   "!B"),
    7:  ("src_port",    "!H"),
    8:  ("src_ip",      "ipv4"),
    10: ("input_snmp",  "!H"),
    11: ("dst_port",    "!H"),
    12: ("dst_ip",      "ipv4"),
    14: ("output_snmp", "!H"),
    21: ("last_sw",     "!I"),
    22: ("first_sw",    "!I"),
    17: ("dst_as",      "!H"),
    16: ("src_as",      "!H"),
}

# Template store: {(source_id, template_id): [(field_type, field_length), ...]}
_v9_templates: dict[tuple[int, int], list[tuple[int, int]]] = {}


def _parse_v9_template_flowset(payload: bytes, source_id: int) -> None:
    offset = 0
    while offset + 4 <= len(payload):
        template_id = struct.unpack_from("!H", payload, offset)[0]
        field_count = struct.unpack_from("!H", payload, offset + 2)[0]
        offset += 4
        if field_count == 0:
            continue
        fields: list[tuple[int, int]] = []
        for _ in range(field_count):
            if offset + 4 > len(payload):
                break
            ftype  = struct.unpack_from("!H", payload, offset)[0]
            flen   = struct.unpack_from("!H", payload, offset + 2)[0]
            fields.append((ftype, flen))
            offset += 4
        if fields:
            _v9_templates[(source_id, template_id)] = fields
            logger.debug(f"NetFlow v9 template kayıt: src={source_id} tpl={template_id} fields={len(fields)}")


def _parse_v9_data_flowset(
    payload: bytes,
    template_id: int,
    source_id: int,
    unix_secs: int,
    source_host: str,
) -> list[NormalizedLog]:
    template = _v9_templates.get((source_id, template_id))
    if template is None:
        return []

    record_size = sum(flen for _, flen in template)
    if record_size == 0:
        return []

    logs = []
    offset = 0
    while offset + record_size <= len(payload):
        fields: dict[str, object] = {}
        rec_off = offset
        for ftype, flen in template:
            chunk = payload[rec_off: rec_off + flen]
            name, fmt = _V9_FIELD_TYPES.get(ftype, (str(ftype), None))
            if fmt == "ipv4" and len(chunk) == 4:
                fields[name] = socket.inet_ntoa(chunk)
            elif fmt and fmt != "ipv4":
                try:
                    fields[name] = struct.unpack(fmt, chunk[:struct.calcsize(fmt)])[0]
                except struct.error:
                    pass
            rec_off += flen
        offset += record_size

        src_ip   = str(fields.get("src_ip", ""))
        dst_ip   = str(fields.get("dst_ip", ""))
        src_port = int(fields.get("src_port", 0))
        dst_port = int(fields.get("dst_port", 0))
        proto_n  = int(fields.get("protocol", 0))
        packets  = int(fields.get("in_pkts", 0))
        octets   = int(fields.get("in_bytes", 0))

        if not src_ip or not dst_ip:
            continue

        extra = {
            "version":    9,
            "template_id": template_id,
            "tcp_flags":  fields.get("tcp_flags", 0),
            "tos":        fields.get("tos", 0),
        }
        logs.append(_make_log(
            source_host = source_host,
            src_ip      = src_ip,
            dst_ip      = dst_ip,
            src_port    = src_port,
            dst_port    = dst_port,
            proto_num   = proto_n,
            packets     = packets,
            octets      = octets,
            unix_secs   = unix_secs,
            extra       = extra,
        ))
    return logs


def parse_v9(data: bytes, source_host: str) -> list[NormalizedLog]:
    if len(data) < _V9_HEADER.size:
        return []
    hdr = _V9_HEADER.unpack_from(data, 0)
    version = hdr[0]
    if version != 9:
        return []
    unix_secs = hdr[3]
    source_id = hdr[5]

    logs = []
    offset = _V9_HEADER.size
    while offset + 4 <= len(data):
        flowset_id, length = _V9_FLOWSET_HDR.unpack_from(data, offset)
        if length < 4:
            break
        payload = data[offset + 4: offset + length]
        if flowset_id == 0:
            _parse_v9_template_flowset(payload, source_id)
        elif flowset_id >= 256:
            logs.extend(_parse_v9_data_flowset(
                payload, flowset_id, source_id, unix_secs, source_host
            ))
        offset += length
    return logs


# ── Otomatik tespit ───────────────────────────────────────────────────────────

def detect_and_parse(data: bytes, source_host: str) -> list[NormalizedLog]:
    if len(data) < 2:
        return []
    version = struct.unpack_from("!H", data, 0)[0]
    if version == 5:
        return parse_v5(data, source_host)
    if version == 9:
        return parse_v9(data, source_host)
    return []
