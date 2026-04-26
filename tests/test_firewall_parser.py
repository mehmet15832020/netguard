"""Firewall log parser testleri."""

import pytest
from server.parsers.firewall import (
    parse_pfsense, parse_cisco_asa, parse_fortigate,
    parse_opnsense, parse_vyos, detect_and_parse,
)


PFSENSE_BLOCK = (
    "Apr 24 10:00:01 pfsense filterlog: 5,,,123,em0,match,block,in,4,"
    "0x0,,64,0,0,DF,17,udp,328,1.2.3.4,192.168.1.1,12345,53,308"
)
PFSENSE_PASS = (
    "Apr 24 10:00:02 pfsense filterlog: 5,,,124,em0,match,pass,out,4,"
    "0x0,,64,0,0,DF,6,tcp,328,192.168.1.10,8.8.8.8,54321,443,308"
)
ASA_DENY = (
    "Apr 24 10:00:01 asa1 %ASA-2-106001: Inbound TCP connection denied "
    "from 1.2.3.4/80 to 192.168.1.1/443 flags SYN"
)
ASA_PERMIT = (
    "Apr 24 10:00:01 asa1 %ASA-6-302013: Built inbound TCP connection 123 "
    "for outside:1.2.3.4/80 to inside:192.168.1.1/443"
)
FORTI_DENY = (
    'date=2024-04-24 time=10:00:01 devname=FGT logid=0000000013 '
    'type=traffic subtype=forward level=notice srcip=5.6.7.8 srcport=12345 '
    'dstip=192.168.1.1 dstport=443 proto=6 action=deny policyid=5'
)
FORTI_ALLOW = (
    'date=2024-04-24 time=10:00:02 devname=FGT logid=0000000013 '
    'type=traffic subtype=forward level=notice srcip=10.0.0.1 srcport=54321 '
    'dstip=8.8.8.8 dstport=53 proto=17 action=accept policyid=1'
)

OPNSENSE_BLOCK = (
    '<134>Apr 26 10:00:01 OPNsense filterlog[12345]: '
    '82,,,0,vtnet1,match,block,in,4,0x0,,128,12345,0,none,17,udp,60,'
    '1.2.3.4,10.0.30.1,54321,53,40'
)
OPNSENSE_PASS = (
    '<134>Apr 26 10:00:02 OPNsense filterlog[12346]: '
    '82,,,0,vtnet1,match,pass,out,4,0x0,,128,12346,0,none,6,tcp,60,'
    '10.0.10.2,8.8.8.8,45678,443,40'
)

VYOS_DROP = (
    'Apr 26 10:00:01 vyos kernel: [VyOS-FW-DROP] IN=eth0 OUT= '
    'MAC=52:54:00:ab:cd:ef:52:54:00:12:34:56:08:00 '
    'SRC=10.0.30.1 DST=192.168.1.1 LEN=52 TOS=0x00 PREC=0x00 TTL=63 ID=0 '
    'PROTO=TCP SPT=12345 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0'
)
VYOS_ACCEPT = (
    'Apr 26 10:00:02 vyos kernel: [VyOS-FW-ACCEPT] IN=eth0 OUT=eth1 '
    'SRC=10.0.10.2 DST=8.8.8.8 LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=0 '
    'PROTO=UDP SPT=54321 DPT=53 LENGTH=28'
)


class TestPfSenseParser:
    def test_block_parsed(self):
        log = parse_pfsense(PFSENSE_BLOCK)
        assert log is not None
        assert log.event_type == "fw_block"
        assert log.severity == "warning"
        assert log.src_ip == "1.2.3.4"
        assert log.dst_ip == "192.168.1.1"
        assert log.src_port == 12345

    def test_pass_parsed(self):
        log = parse_pfsense(PFSENSE_PASS)
        assert log is not None
        assert log.event_type == "fw_allow"
        assert log.severity == "info"

    def test_non_pfsense_returns_none(self):
        assert parse_pfsense("random syslog line") is None

    def test_source_type(self):
        log = parse_pfsense(PFSENSE_BLOCK)
        assert log.source_type == "pfsense"


class TestCiscoASAParser:
    def test_deny_parsed(self):
        log = parse_cisco_asa(ASA_DENY)
        assert log is not None
        assert log.event_type == "fw_block"
        assert log.src_ip == "1.2.3.4"
        assert log.src_port == 80
        assert log.dst_ip == "192.168.1.1"
        assert log.dst_port == 443

    def test_permit_parsed(self):
        log = parse_cisco_asa(ASA_PERMIT)
        assert log is not None
        assert log.event_type == "fw_allow"

    def test_severity_from_level(self):
        log = parse_cisco_asa(ASA_DENY)
        assert log.severity in ("high", "warning", "critical")

    def test_non_asa_returns_none(self):
        assert parse_cisco_asa("filterlog: something") is None


class TestFortiGateParser:
    def test_deny_parsed(self):
        log = parse_fortigate(FORTI_DENY)
        assert log is not None
        assert log.event_type == "fw_block"
        assert log.src_ip == "5.6.7.8"
        assert log.dst_port == 443
        assert log.severity == "warning"

    def test_allow_parsed(self):
        log = parse_fortigate(FORTI_ALLOW)
        assert log is not None
        assert log.event_type == "fw_allow"

    def test_devname_as_source_host(self):
        log = parse_fortigate(FORTI_DENY)
        assert log.source_host == "FGT"

    def test_non_forti_returns_none(self):
        assert parse_fortigate("random line") is None


class TestOPNsenseParser:
    def test_block_parsed(self):
        log = parse_opnsense(OPNSENSE_BLOCK)
        assert log is not None
        assert log.event_type == "fw_block"
        assert log.severity == "warning"
        assert log.src_ip == "1.2.3.4"
        assert log.dst_ip == "10.0.30.1"
        assert log.src_port == 54321
        assert log.dst_port == 53

    def test_pass_parsed(self):
        log = parse_opnsense(OPNSENSE_PASS)
        assert log is not None
        assert log.event_type == "fw_allow"
        assert log.severity == "info"
        assert log.dst_port == 443

    def test_source_type_is_opnsense(self):
        log = parse_opnsense(OPNSENSE_BLOCK)
        assert log.source_type == "opnsense"

    def test_source_host_extracted(self):
        log = parse_opnsense(OPNSENSE_BLOCK)
        assert log.source_host == "OPNsense"

    def test_non_opnsense_returns_none(self):
        assert parse_opnsense("Apr 24 10:00:01 pfsense filterlog: 5,,,123,em0") is None


class TestVyOSParser:
    def test_drop_parsed(self):
        log = parse_vyos(VYOS_DROP)
        assert log is not None
        assert log.event_type == "fw_block"
        assert log.severity == "warning"
        assert log.src_ip == "10.0.30.1"
        assert log.dst_ip == "192.168.1.1"
        assert log.src_port == 12345
        assert log.dst_port == 443

    def test_accept_parsed(self):
        log = parse_vyos(VYOS_ACCEPT)
        assert log is not None
        assert log.event_type == "fw_allow"
        assert log.severity == "info"
        assert log.src_ip == "10.0.10.2"
        assert log.dst_port == 53

    def test_source_type_is_vyos(self):
        log = parse_vyos(VYOS_DROP)
        assert log.source_type == "vyos"

    def test_protocol_extracted(self):
        log = parse_vyos(VYOS_DROP)
        assert log.protocol == "tcp"
        log2 = parse_vyos(VYOS_ACCEPT)
        assert log2.protocol == "udp"

    def test_non_vyos_returns_none(self):
        assert parse_vyos("random syslog line without SRC DST") is None


class TestAutoDetect:
    def test_detects_pfsense(self):
        log = detect_and_parse(PFSENSE_BLOCK)
        assert log is not None and log.source_type == "pfsense"

    def test_detects_opnsense(self):
        log = detect_and_parse(OPNSENSE_BLOCK)
        assert log is not None and log.source_type == "opnsense"

    def test_detects_asa(self):
        log = detect_and_parse(ASA_DENY)
        assert log is not None and log.source_type == "cisco_asa"

    def test_detects_fortigate(self):
        log = detect_and_parse(FORTI_DENY)
        assert log is not None and log.source_type == "fortigate"

    def test_detects_vyos(self):
        log = detect_and_parse(VYOS_DROP)
        assert log is not None and log.source_type == "vyos"

    def test_unknown_returns_none(self):
        assert detect_and_parse("this is not a firewall log") is None
