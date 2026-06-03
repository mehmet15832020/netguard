"""
NetGuard — NetFlow v5 / v9 Binary Parser

NetFlow v5: Sabit boyutlu kayıtlar (24 byte header + 48 byte/flow)
NetFlow v9: Template tabanlı — önce template alınır, sonra data parse edilir

Her parse çağrısı list[NormalizedLog] döner (birden fazla akış olabilir).
"""

import logging
import os
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

# Protokol tünel setleri — T1572 (Protocol Tunneling): GRE, ESP, IPv6-in-IPv4
_TUNNELED_PROTOCOLS = {47, 50, 41}

# Büyük akış eşiği — T1048 (Exfil Over Alt Protocol); env ile geçersiz kılınabilir
_LARGE_FLOW_BYTES: int = int(os.environ.get("NETFLOW_LARGE_FLOW_BYTES", str(50 * 1024 * 1024)))


def _ip_from_int(n: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", n))


def _event_action_for_flow(
    proto_num: int,
    destination_port: int,
    source_port: int,
    octets: int,
) -> str:
    """Akış özelliklerine göre event_action döner (öncelik sırası korunur)."""
    if octets > _LARGE_FLOW_BYTES:
        return "netflow_large_flow"
    if proto_num in _TUNNELED_PROTOCOLS:
        return "netflow_tunneled"
    if destination_port in _SUSPICIOUS_PORTS or source_port in _SUSPICIOUS_PORTS:
        return "netflow_suspicious_port"
    return "netflow_flow"


def _severity_for_flow(proto: str, destination_port: int, source_port: int) -> str:
    if destination_port in _SUSPICIOUS_PORTS or source_port in _SUSPICIOUS_PORTS:
        return "warning"
    return "info"


def _make_log(
    observer_hostname: str,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    proto_num: int,
    packets: int,
    octets: int,
    unix_secs: int,
    extra: dict,
) -> NormalizedLog:
    proto = _PROTO_MAP.get(proto_num, str(proto_num))
    severity = _severity_for_flow(proto, destination_port, source_port)
    ts = datetime.fromtimestamp(unix_secs, tz=timezone.utc)
    action = _event_action_for_flow(proto_num, destination_port, source_port, octets)

    return NormalizedLog(
        log_id      = str(uuid.uuid4()),
        raw_id      = str(uuid.uuid4()),
        source_type = LogSourceType.NETFLOW,
        observer_hostname = observer_hostname,
        timestamp   = ts,
        severity    = severity,
        event_category    = LogCategory.NETWORK,
        event_action  = action,
        source_ip      = source_ip,
        destination_ip      = destination_ip,
        source_port    = source_port,
        destination_port    = destination_port,
        network_protocol    = proto,
        message     = (
            f"NetFlow {proto.upper()} "
            f"{source_ip}:{source_port} → {destination_ip}:{destination_port} "
            f"({packets} pkts, {octets} B)"
        ),
        tags        = [proto, f"dst:{destination_port}"],
        extra       = {**extra, "packets": packets, "bytes": octets},
        network_bytes = octets or None,
    )


def parse_v5(data: bytes, observer_hostname: str) -> list[NormalizedLog]:
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
            observer_hostname = observer_hostname,
            source_ip      = _ip_from_int(srcaddr),
            destination_ip      = _ip_from_int(dstaddr),
            source_port    = srcport,
            destination_port    = dstport,
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
    4:  ("network_protocol",    "!B"),
    5:  ("tos",         "!B"),
    6:  ("tcp_flags",   "!B"),
    7:  ("source_port",    "!H"),
    8:  ("source_ip",      "ipv4"),
    10: ("input_snmp",  "!H"),
    11: ("destination_port",    "!H"),
    12: ("destination_ip",      "ipv4"),
    14: ("output_snmp", "!H"),
    21: ("last_sw",     "!I"),
    22: ("first_sw",    "!I"),
    17: ("dst_as",      "!H"),
    16: ("src_as",      "!H"),
}

# Template store: {(observer, source_id, template_id): [...]}
# observer key eklendi — farklı exporter'ların aynı template_id kullanması durumunda
# cross-observer template karışmasını önler (RFC 3954 §5).
_v9_templates: dict[tuple[str, int, int], list[tuple[int, int]]] = {}


def _parse_v9_template_flowset(payload: bytes, source_id: int, observer: str = "") -> None:
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
            _v9_templates[(observer, source_id, template_id)] = fields
            logger.debug("NetFlow v9 template: obs=%s src=%d tpl=%d fields=%d",
                         observer, source_id, template_id, len(fields))


def _parse_v9_data_flowset(
    payload: bytes,
    template_id: int,
    source_id: int,
    unix_secs: int,
    observer_hostname: str,
) -> list[NormalizedLog]:
    template = _v9_templates.get((observer_hostname, source_id, template_id))
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

        source_ip   = str(fields.get("source_ip", ""))
        destination_ip   = str(fields.get("destination_ip", ""))
        source_port = int(fields.get("source_port", 0))
        destination_port = int(fields.get("destination_port", 0))
        proto_n  = int(fields.get("network_protocol", 0))
        packets  = int(fields.get("in_pkts", 0))
        octets   = int(fields.get("in_bytes", 0))

        if not source_ip or not destination_ip:
            continue

        extra = {
            "version":    9,
            "template_id": template_id,
            "tcp_flags":  fields.get("tcp_flags", 0),
            "tos":        fields.get("tos", 0),
        }
        logs.append(_make_log(
            observer_hostname = observer_hostname,
            source_ip      = source_ip,
            destination_ip      = destination_ip,
            source_port    = source_port,
            destination_port    = destination_port,
            proto_num   = proto_n,
            packets     = packets,
            octets      = octets,
            unix_secs   = unix_secs,
            extra       = extra,
        ))
    return logs


def parse_v9(data: bytes, observer_hostname: str) -> list[NormalizedLog]:
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
            _parse_v9_template_flowset(payload, source_id, observer_hostname)
        elif flowset_id >= 256:
            logs.extend(_parse_v9_data_flowset(
                payload, flowset_id, source_id, unix_secs, observer_hostname
            ))
        offset += length
    return logs


# ── IPFIX (NetFlow v10) ───────────────────────────────────────────────────────

_IPFIX_HEADER   = struct.Struct("!HHIII")   # version(2)+length(2)+export_time(4)+seq(4)+obs_domain_id(4)
_IPFIX_SET_HDR  = struct.Struct("!HH")      # set_id(2)+length(2)
_IPFIX_TMPL_HDR = struct.Struct("!HH")      # template_id(2)+field_count(2)
_IPFIX_FIELD    = struct.Struct("!HH")      # ie_type(2)+ie_length(2)
_IPFIX_ENT_PEN  = struct.Struct("!I")       # enterprise_id(4)

# IANA IPFIX Information Element IDs (RFC 7012)
_IPFIX_IE: dict[int, str] = {
    1:   "octetDeltaCount",
    2:   "packetDeltaCount",
    4:   "protocolIdentifier",
    6:   "tcpControlBits",
    7:   "sourceTransportPort",
    8:   "sourceIPv4Address",
    10:  "ingressInterface",
    11:  "destinationTransportPort",
    12:  "destinationIPv4Address",
    14:  "egressInterface",
    21:  "flowEndSysUpTime",
    22:  "flowStartSysUpTime",
    27:  "sourceIPv6Address",
    28:  "destinationIPv6Address",
    56:  "sourceMacAddress",
    80:  "destinationMacAddress",
    152: "flowStartMilliseconds",
    153: "flowEndMilliseconds",
    176: "icmpTypeCodeIPv4",
    258: "collectionTimeMilliseconds",
}

# Global IPFIX template cache: (observer, obs_domain_id, template_id) → [...]
# observer key: farklı exporter'ların aynı obs_domain_id+template_id kullanması durumunda karışma önlenir.
_ipfix_templates: dict[tuple[str, int, int], list[tuple[int, int, int, bool]]] = {}

# ── sFlow v5 ──────────────────────────────────────────────────────────────────

_SFLOW_HDR        = struct.Struct("!IIIIIII")  # version(4)+addr_type(4)+agent_ip(4)+sub_id(4)+seq(4)+uptime(4)+num_samples(4)
_SFLOW_SAMPLE_HDR = struct.Struct("!II")        # type(4)+length(4)
_SFLOW_FLOW_HDR   = struct.Struct("!IIIIIIII")  # seq+src_id+rate+pool+drops+input+output+num_records
_SFLOW_RECORD_HDR = struct.Struct("!II")        # record_type(4)+record_length(4)
_SFLOW_IPV4_FLOW  = struct.Struct("!IIIIIIII")  # length+proto+src_ip+dst_ip+src_port+dst_port+tcp_flags+tos (sFlow v5 sampled_ipv4, RFC 3176)


def parse_ipfix(data: bytes, observer_hostname: str) -> list[NormalizedLog]:
    """RFC 7011 IPFIX (NetFlow v10) binary parser. Template-based, multi-domain, enterprise field support."""
    results: list[NormalizedLog] = []
    if len(data) < _IPFIX_HEADER.size:
        return results

    version, total_len, export_time, sequence, obs_domain_id = _IPFIX_HEADER.unpack_from(data, 0)
    if version != 10:
        return results

    offset = _IPFIX_HEADER.size

    while offset + _IPFIX_SET_HDR.size <= len(data):
        set_id, set_length = _IPFIX_SET_HDR.unpack_from(data, offset)
        if set_length < 4 or offset + set_length > len(data):
            break

        set_payload = data[offset + 4: offset + set_length]

        if set_id == 2:
            _ipfix_parse_template(set_payload, obs_domain_id, observer_hostname)
        elif set_id == 3:
            pass  # Options Template — şimdilik skip
        elif set_id >= 256:
            flows = _ipfix_parse_data(set_payload, obs_domain_id, set_id, export_time, observer_hostname)
            results.extend(flows)

        offset += set_length
        # 4-byte padding hizalama
        if set_length % 4:
            offset += 4 - (set_length % 4)

    return results


def _ipfix_parse_template(payload: bytes, obs_domain_id: int, observer: str = "") -> None:
    offset = 0
    while offset + _IPFIX_TMPL_HDR.size <= len(payload):
        template_id, field_count = _IPFIX_TMPL_HDR.unpack_from(payload, offset)
        offset += _IPFIX_TMPL_HDR.size

        if field_count == 0 or template_id < 256:
            continue

        fields: list[tuple[int, int, int, bool]] = []
        for _ in range(field_count):
            if offset + _IPFIX_FIELD.size > len(payload):
                break
            raw_type, ie_len = _IPFIX_FIELD.unpack_from(payload, offset)
            offset += _IPFIX_FIELD.size
            is_enterprise = bool(raw_type & 0x8000)
            ie_type = raw_type & 0x7FFF
            pen = 0
            if is_enterprise:
                if offset + _IPFIX_ENT_PEN.size > len(payload):
                    break
                pen = _IPFIX_ENT_PEN.unpack_from(payload, offset)[0]
                offset += _IPFIX_ENT_PEN.size
            fields.append((ie_type, ie_len, pen, is_enterprise))

        _ipfix_templates[(observer, obs_domain_id, template_id)] = fields
        logger.debug("IPFIX template: obs=%s domain=%d tpl=%d fields=%d",
                     observer, obs_domain_id, template_id, len(fields))


def _ipfix_parse_data(
    payload: bytes,
    obs_domain_id: int,
    template_id: int,
    export_time: int,
    observer_hostname: str,
) -> list[NormalizedLog]:
    results: list[NormalizedLog] = []
    template = _ipfix_templates.get((observer_hostname, obs_domain_id, template_id))
    if not template:
        logger.debug("IPFIX: template not found obs=%s domain=%d tpl=%d",
                     observer_hostname, obs_domain_id, template_id)
        return results

    # Variable-length IE (RFC 7011 §7, ie_len==65535) içeren template'leri
    # şimdilik atla — yanlış byte hizalamasından korunmak için.
    if any(ie_len == 65535 for (_, ie_len, _, _) in template):
        logger.debug("IPFIX: variable-length IE içeren template atlandı domain=%d tpl=%d",
                     obs_domain_id, template_id)
        return results

    fixed_size = sum(ie_len for (_, ie_len, _, _) in template)
    if fixed_size == 0 or fixed_size > len(payload):
        return results

    offset = 0
    while offset + fixed_size <= len(payload):
        record: dict[str, object] = {}
        pos = offset
        for ie_type, ie_len, pen, is_enterprise in template:
            if pos + ie_len > len(payload):
                break
            raw = payload[pos: pos + ie_len]
            pos += ie_len

            if is_enterprise:
                record[f"pen_{pen}_{ie_type}"] = int.from_bytes(raw, "big")
            else:
                ie_name = _IPFIX_IE.get(ie_type, f"ie_{ie_type}")
                if ie_len == 4 and ie_type in (8, 12):
                    try:
                        record[ie_name] = socket.inet_ntop(socket.AF_INET, raw)
                    except Exception:
                        record[ie_name] = int.from_bytes(raw, "big")
                elif ie_len == 16 and ie_type in (27, 28):
                    try:
                        record[ie_name] = socket.inet_ntop(socket.AF_INET6, raw)
                    except Exception:
                        record[ie_name] = ""
                else:
                    record[ie_name] = int.from_bytes(raw, "big")

        offset += fixed_size

        src_ip   = record.get("sourceIPv4Address") or record.get("sourceIPv6Address")
        dst_ip   = record.get("destinationIPv4Address") or record.get("destinationIPv6Address")
        proto_n  = int(record.get("protocolIdentifier", 0))
        src_port = int(record.get("sourceTransportPort", 0)) or None
        dst_port = int(record.get("destinationTransportPort", 0)) or None
        bytes_   = int(record.get("octetDeltaCount", 0))
        packets  = int(record.get("packetDeltaCount", 0))

        if not src_ip or not dst_ip:
            continue

        proto_name = _PROTO_MAP.get(proto_n, str(proto_n))
        event_action, severity = _event_action_for_ipfix(proto_n, dst_port, bytes_)

        results.append(NormalizedLog(
            log_id            = str(uuid.uuid4()),
            raw_id            = str(uuid.uuid4()),
            source_type       = LogSourceType.NETFLOW,
            observer_hostname = observer_hostname,
            timestamp         = datetime.fromtimestamp(export_time, tz=timezone.utc),
            severity          = severity,
            event_category    = LogCategory.NETWORK,
            event_action      = event_action,
            source_ip         = str(src_ip),
            destination_ip    = str(dst_ip),
            source_port       = src_port,
            destination_port  = dst_port,
            network_protocol  = proto_name,
            network_bytes     = bytes_ or None,
            message           = (
                f"IPFIX {proto_name} {src_ip}:{src_port or '?'}"
                f" → {dst_ip}:{dst_port or '?'}"
                f" bytes={bytes_} pkts={packets}"
            ),
            tags  = ["ipfix", "netflow_v10"],
            extra = {
                "version":        10,
                "obs_domain_id":  obs_domain_id,
                "template_id":    template_id,
                "packets":        packets,
                "protocol_number": proto_n,
            },
        ))

    return results


def _event_action_for_ipfix(proto: int, dst_port: int | None, bytes_: int) -> tuple[str, str]:
    large_threshold = int(os.environ.get("NETFLOW_LARGE_FLOW_BYTES", str(50 * 1024 * 1024)))
    if bytes_ >= large_threshold:
        return "netflow_large_flow", "warning"
    if proto in _TUNNELED_PROTOCOLS:
        return "netflow_tunneled", "warning"
    if dst_port and dst_port in _SUSPICIOUS_PORTS:
        return "netflow_suspicious_port", "warning"
    return "netflow_flow", "info"


def parse_sflow(data: bytes, observer_hostname: str) -> list[NormalizedLog]:
    """RFC 3176 / sFlow v5 sampled flow parser. Flow Sample (type=1/3) → IPv4 flow records → NormalizedLog."""
    results: list[NormalizedLog] = []
    if len(data) < _SFLOW_HDR.size:
        return results

    try:
        version, addr_type, agent_ip_int, sub_id, seq, uptime, num_samples = _SFLOW_HDR.unpack_from(data, 0)
    except struct.error:
        return results

    if version != 5:
        return results

    try:
        agent_ip = socket.inet_ntoa(struct.pack("!I", agent_ip_int))
    except Exception:
        agent_ip = observer_hostname

    offset = _SFLOW_HDR.size

    for _ in range(num_samples):
        if offset + _SFLOW_SAMPLE_HDR.size > len(data):
            break
        sample_type, sample_length = _SFLOW_SAMPLE_HDR.unpack_from(data, offset)
        offset += _SFLOW_SAMPLE_HDR.size
        sample_end = offset + sample_length

        if sample_end > len(data):
            break

        # Flow Sample (type=1) — Expanded Flow Sample (type=3) farklı header
        # boyutuna sahip (source_id 2×4, input/output 2×4 byte); yanlış parse
        # önlemek için type=3 şimdilik atlanıyor (RFC 3176 §5.1).
        if sample_type == 1:
            flows = _sflow_parse_flow_sample(data[offset:sample_end], agent_ip, observer_hostname)
            results.extend(flows)
        elif sample_type == 3:
            logger.debug("sFlow: expanded flow sample (type=3) atlandı")

        offset = sample_end

    return results


def _sflow_parse_flow_sample(payload: bytes, agent_ip: str, observer_hostname: str) -> list[NormalizedLog]:
    results: list[NormalizedLog] = []
    if len(payload) < _SFLOW_FLOW_HDR.size:
        return results

    try:
        seq, src_id, rate, pool, drops, input_if, output_if, num_records = \
            _SFLOW_FLOW_HDR.unpack_from(payload, 0)
    except struct.error:
        return results

    offset = _SFLOW_FLOW_HDR.size

    for _ in range(num_records):
        if offset + _SFLOW_RECORD_HDR.size > len(payload):
            break
        record_type, record_length = _SFLOW_RECORD_HDR.unpack_from(payload, offset)
        offset += _SFLOW_RECORD_HDR.size
        record_end = offset + record_length

        if record_end > len(payload):
            break

        # IPv4 Flow Record (type=3)
        if record_type == 3 and record_length >= _SFLOW_IPV4_FLOW.size:
            try:
                length, proto, src_ip_int, dst_ip_int, src_port, dst_port, tcp_flags, tos = \
                    _SFLOW_IPV4_FLOW.unpack_from(payload, offset)
                src_ip = socket.inet_ntoa(struct.pack("!I", src_ip_int))
                dst_ip = socket.inet_ntoa(struct.pack("!I", dst_ip_int))

                if src_ip and dst_ip:
                    proto_name = _PROTO_MAP.get(proto, str(proto))
                    event_action, severity = _event_action_for_sflow(proto, dst_port, length)

                    results.append(NormalizedLog(
                        log_id            = str(uuid.uuid4()),
                        raw_id            = str(uuid.uuid4()),
                        source_type       = LogSourceType.SFLOW,
                        observer_hostname = observer_hostname or agent_ip,
                        timestamp         = datetime.now(timezone.utc),
                        severity          = severity,
                        event_category    = LogCategory.NETWORK,
                        event_action      = event_action,
                        source_ip         = src_ip,
                        destination_ip    = dst_ip,
                        source_port       = src_port or None,
                        destination_port  = dst_port or None,
                        network_protocol  = proto_name,
                        network_bytes     = length or None,
                        message           = (
                            f"sFlow {proto_name} {src_ip}:{src_port or '?'}"
                            f" → {dst_ip}:{dst_port or '?'}"
                            f" sample_rate={rate}"
                        ),
                        tags  = ["sflow"],
                        extra = {
                            "agent_ip":   agent_ip,
                            "sample_rate": rate,
                            "input_if":   input_if,
                            "output_if":  output_if,
                            "tcp_flags":  tcp_flags,
                            "tos":        tos,
                        },
                    ))
            except struct.error:
                pass

        offset = record_end

    return results


def _event_action_for_sflow(proto: int, dst_port: int, bytes_: int) -> tuple[str, str]:
    large_threshold = int(os.environ.get("NETFLOW_LARGE_FLOW_BYTES", str(50 * 1024 * 1024)))
    if bytes_ >= large_threshold:
        return "sflow_large_flow", "warning"
    if proto in _TUNNELED_PROTOCOLS:
        return "sflow_tunneled", "warning"
    if dst_port and dst_port in _SUSPICIOUS_PORTS:
        return "sflow_suspicious_port", "warning"
    return "sflow_flow", "info"


# ── Otomatik tespit ───────────────────────────────────────────────────────────

def detect_and_parse(data: bytes, observer_hostname: str) -> list[NormalizedLog]:
    if len(data) < 2:
        return []
    version = struct.unpack_from("!H", data, 0)[0]
    if version == 5:
        return parse_v5(data, observer_hostname)
    if version == 9:
        return parse_v9(data, observer_hostname)
    if version == 10:
        return parse_ipfix(data, observer_hostname)
    return []
