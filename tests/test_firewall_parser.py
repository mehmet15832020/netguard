"""Firewall log parser testleri."""

import pytest
from server.parsers.firewall import (
    parse_pfsense, parse_cisco_asa, parse_fortigate,
    parse_opnsense, parse_vyos, detect_and_parse,
    parse_isc_dhcpd, parse_kea_dhcp, parse_fortigate_dhcp, parse_dhcp_syslog,
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
        assert log.event_action == "fw_block"
        assert log.severity == "warning"
        assert log.source_ip == "1.2.3.4"
        assert log.destination_ip == "192.168.1.1"
        assert log.source_port == 12345

    def test_pass_parsed(self):
        log = parse_pfsense(PFSENSE_PASS)
        assert log is not None
        assert log.event_action == "fw_allow"
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
        assert log.event_action == "fw_block"
        assert log.source_ip == "1.2.3.4"
        assert log.source_port == 80
        assert log.destination_ip == "192.168.1.1"
        assert log.destination_port == 443

    def test_permit_parsed(self):
        log = parse_cisco_asa(ASA_PERMIT)
        assert log is not None
        assert log.event_action == "fw_allow"

    def test_severity_from_level(self):
        log = parse_cisco_asa(ASA_DENY)
        assert log.severity in ("high", "warning", "critical")

    def test_non_asa_returns_none(self):
        assert parse_cisco_asa("filterlog: something") is None


class TestFortiGateParser:
    def test_deny_parsed(self):
        log = parse_fortigate(FORTI_DENY)
        assert log is not None
        assert log.event_action == "fw_block"
        assert log.source_ip == "5.6.7.8"
        assert log.destination_port == 443
        assert log.severity == "warning"

    def test_allow_parsed(self):
        log = parse_fortigate(FORTI_ALLOW)
        assert log is not None
        assert log.event_action == "fw_allow"

    def test_devname_as_source_host(self):
        log = parse_fortigate(FORTI_DENY)
        assert log.observer_hostname == "FGT"

    def test_non_forti_returns_none(self):
        assert parse_fortigate("random line") is None


class TestOPNsenseParser:
    def test_block_parsed(self):
        log = parse_opnsense(OPNSENSE_BLOCK)
        assert log is not None
        assert log.event_action == "fw_block"
        assert log.severity == "warning"
        assert log.source_ip == "1.2.3.4"
        assert log.destination_ip == "10.0.30.1"
        assert log.source_port == 54321
        assert log.destination_port == 53

    def test_pass_parsed(self):
        log = parse_opnsense(OPNSENSE_PASS)
        assert log is not None
        assert log.event_action == "fw_allow"
        assert log.severity == "info"
        assert log.destination_port == 443

    def test_source_type_is_opnsense(self):
        log = parse_opnsense(OPNSENSE_BLOCK)
        assert log.source_type == "opnsense"

    def test_source_host_extracted(self):
        log = parse_opnsense(OPNSENSE_BLOCK)
        assert log.observer_hostname == "OPNsense"

    def test_non_opnsense_returns_none(self):
        assert parse_opnsense("Apr 24 10:00:01 pfsense filterlog: 5,,,123,em0") is None


class TestVyOSParser:
    def test_drop_parsed(self):
        log = parse_vyos(VYOS_DROP)
        assert log is not None
        assert log.event_action == "fw_block"
        assert log.severity == "warning"
        assert log.source_ip == "10.0.30.1"
        assert log.destination_ip == "192.168.1.1"
        assert log.source_port == 12345
        assert log.destination_port == 443

    def test_accept_parsed(self):
        log = parse_vyos(VYOS_ACCEPT)
        assert log is not None
        assert log.event_action == "fw_allow"
        assert log.severity == "info"
        assert log.source_ip == "10.0.10.2"
        assert log.destination_port == 53

    def test_source_type_is_vyos(self):
        log = parse_vyos(VYOS_DROP)
        assert log.source_type == "vyos"

    def test_protocol_extracted(self):
        log = parse_vyos(VYOS_DROP)
        assert log.network_protocol == "tcp"
        log2 = parse_vyos(VYOS_ACCEPT)
        assert log2.network_protocol == "udp"

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

    def test_detects_isc_dhcpd_via_detect_and_parse(self):
        log = detect_and_parse(
            "Apr 24 10:00:01 opnsense dhcpd: DHCPACK on 192.168.1.50 to "
            "aa:bb:cc:dd:ee:ff (myhost) via igb0"
        )
        assert log is not None
        assert log.source_type == "dhcp"
        assert log.event_action == "dhcp_lease"


# ── F1 — DHCP syslog parser'ları (marka bağımsız) ──────────────────────────

ISC_DHCPD_ACK = (
    "Apr 24 10:00:01 opnsense dhcpd: DHCPACK on 192.168.1.50 to "
    "aa:bb:cc:dd:ee:ff (myhost) via igb0"
)
ISC_DHCPD_NAK = (
    "Apr 24 10:00:01 opnsense dhcpd: DHCPNAK on 192.168.1.50 to "
    "aa:bb:cc:dd:ee:ff via igb0"
)
ISC_DHCPD_DECLINE = (
    "Apr 24 10:00:01 vyos dhcpd: DHCPDECLINE of 192.168.1.50 from "
    "aa:bb:cc:dd:ee:ff via eth0"
)
ISC_DHCPD_DISCOVER = (
    "Apr 24 10:00:01 opnsense dhcpd: DHCPDISCOVER from aa:bb:cc:dd:ee:ff via igb0"
)
KEA_LEASE_ALLOC = (
    "Apr 24 10:00:01 opnsense kea-dhcp4: INFO  [kea-dhcp4.leases] "
    "DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:ff], cid=[no info], tid=0x1: "
    "lease 192.168.1.60 has been allocated"
)
KEA_LEASE_RENEW = (
    "Apr 24 10:00:01 opnsense kea-dhcp4: INFO  [kea-dhcp4.leases] "
    "DHCP4_LEASE_RENEW [hwtype=1 aa:bb:cc:dd:ee:ff], cid=[no info], tid=0x1: "
    "lease 192.168.1.60 has been renewed"
)
FORTI_DHCP = (
    'date=2026-06-16 time=10:00:01 devname="FG1" type="event" subtype="dhcp" '
    'action="lease" ip=192.168.1.70 mac="aa:bb:cc:dd:ee:ff" hostname="forti-host"'
)
FORTI_DHCP_DECLINE = (
    'date=2026-06-16 time=10:00:01 devname="FG1" type="event" subtype="dhcp" '
    'action="decline" ip=192.168.1.70 mac="aa:bb:cc:dd:ee:ff"'
)


class TestIscDhcpdParser:
    def test_ack_parsed(self):
        log = parse_isc_dhcpd(ISC_DHCPD_ACK)
        assert log is not None
        assert log.source_type == "dhcp"
        assert log.event_action == "dhcp_lease"
        assert log.source_ip == "192.168.1.50"
        assert log.extra["mac"] == "aa:bb:cc:dd:ee:ff"
        assert log.extra["hostname"] == "myhost"
        assert log.severity == "info"

    def test_nak_is_warning(self):
        log = parse_isc_dhcpd(ISC_DHCPD_NAK)
        assert log.severity == "warning"
        assert log.extra["hostname"] == ""

    def test_decline_is_warning(self):
        log = parse_isc_dhcpd(ISC_DHCPD_DECLINE)
        assert log.severity == "warning"
        assert log.source_ip == "192.168.1.50"

    def test_discover_skipped_as_noise(self):
        """DISCOVER/OFFER/REQUEST/RELEASE protokol adımı — lease sonucu taşımaz."""
        assert parse_isc_dhcpd(ISC_DHCPD_DISCOVER) is None

    def test_observer_hostname_extracted(self):
        log = parse_isc_dhcpd(ISC_DHCPD_ACK)
        assert log.observer_hostname == "opnsense"

    def test_vyos_observer_hostname(self):
        log = parse_isc_dhcpd(ISC_DHCPD_DECLINE)
        assert log.observer_hostname == "vyos"

    def test_no_mac_returns_none(self):
        assert parse_isc_dhcpd("dhcpd: DHCPACK on 192.168.1.50 via igb0") is None

    def test_tags(self):
        log = parse_isc_dhcpd(ISC_DHCPD_ACK)
        assert "dhcp" in log.tags
        assert "isc-dhcpd" in log.tags


class TestKeaDhcpParser:
    def test_alloc_parsed(self):
        log = parse_kea_dhcp(KEA_LEASE_ALLOC)
        assert log is not None
        assert log.source_type == "dhcp"
        assert log.event_action == "dhcp_lease"
        assert log.source_ip == "192.168.1.60"
        assert log.extra["mac"] == "aa:bb:cc:dd:ee:ff"
        assert "kea" in log.tags

    def test_renew_parsed(self):
        log = parse_kea_dhcp(KEA_LEASE_RENEW)
        assert log is not None
        assert "renew" in log.tags

    def test_unrelated_line_returns_none(self):
        assert parse_kea_dhcp("some unrelated kea log line") is None

    def test_severity_always_info(self):
        log = parse_kea_dhcp(KEA_LEASE_ALLOC)
        assert log.severity == "info"


class TestFortiGateDhcpParser:
    def test_lease_parsed(self):
        log = parse_fortigate_dhcp(FORTI_DHCP)
        assert log is not None
        assert log.source_type == "dhcp"
        assert log.source_ip == "192.168.1.70"
        assert log.extra["mac"] == "aa:bb:cc:dd:ee:ff"
        assert log.extra["hostname"] == "forti-host"
        assert log.severity == "info"

    def test_decline_is_warning(self):
        log = parse_fortigate_dhcp(FORTI_DHCP_DECLINE)
        assert log.severity == "warning"

    def test_non_dhcp_subtype_returns_none(self):
        assert parse_fortigate_dhcp(FORTI_DENY) is None

    def test_missing_mac_returns_none(self):
        line = FORTI_DHCP.replace('mac="aa:bb:cc:dd:ee:ff" ', '')
        assert parse_fortigate_dhcp(line) is None


class TestDhcpSyslogDispatcher:
    def test_dispatches_isc_dhcpd(self):
        log = parse_dhcp_syslog(ISC_DHCPD_ACK)
        assert log is not None
        assert "isc-dhcpd" in log.tags

    def test_dispatches_kea(self):
        log = parse_dhcp_syslog(KEA_LEASE_ALLOC)
        assert log is not None
        assert "kea" in log.tags

    def test_dispatches_fortigate(self):
        log = parse_dhcp_syslog(FORTI_DHCP)
        assert log is not None
        assert "fortigate" in log.tags

    def test_unrelated_line_returns_none(self):
        assert parse_dhcp_syslog("this is not a dhcp log") is None
