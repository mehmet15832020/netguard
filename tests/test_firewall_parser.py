"""Firewall log parser testleri."""

import pytest
from server.parsers.firewall import (
    parse_pfsense, parse_cisco_asa, parse_fortigate,
    parse_opnsense, parse_vyos, detect_and_parse,
    parse_isc_dhcpd, parse_kea_dhcp, parse_fortigate_dhcp, parse_dhcp_syslog,
    parse_unbound_dns, parse_dnsmasq_dns, parse_fortigate_dns, parse_dns_resolver_syslog,
    parse_fortigate_admin_access, parse_cisco_asa_admin_access,
    parse_pfsense_admin_access, parse_vyos_admin_access, parse_fw_admin_access,
    parse_cisco_ios_routing, parse_juniper_routing, parse_mikrotik_interface,
    parse_fortigate_interface_event, parse_vyos_routing_events, parse_router_event,
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


# ── F2 — DNS resolver syslog parser'ları (marka bağımsız) ──────────────────

UNBOUND_QUERY = "Apr 24 10:00:01 opnsense unbound: [1553775590] unbound[32655:0] info: 192.168.1.10 evil.com. A IN"
DNSMASQ_QUERY = "Apr 24 10:00:01 router dnsmasq[1234]: query[A] evil.com from 192.168.1.10"
FORTI_DNS_PASS = (
    'date=2026-06-16 time=10:00:01 devname="FG1" type="utm" subtype="dns" '
    'eventtype="dns-response" srcip=192.168.1.20 dstip=8.8.8.8 qname="evil.com" '
    'qtype="A" ipaddr=1.2.3.4 action="pass" catdesc="Malicious Websites"'
)
FORTI_DNS_BLOCK = (
    'date=2026-06-16 time=10:00:01 devname="FG1" type="utm" subtype="dns" '
    'eventtype="dns-response" srcip=192.168.1.20 qname="evil.com" qtype="A" '
    'action="block"'
)


class TestUnboundDnsParser:
    def test_query_parsed(self):
        log = parse_unbound_dns(UNBOUND_QUERY)
        assert log is not None
        assert log.source_type == "dns_resolver"
        assert log.event_action == "dns_query"
        assert log.source_ip == "192.168.1.10"
        assert log.extra["query_domain"] == "evil.com"
        assert log.extra["query_type"] == "A"
        assert log.severity == "info"

    def test_unrelated_line_returns_none(self):
        assert parse_unbound_dns("this is not unbound") is None

    def test_tags(self):
        log = parse_unbound_dns(UNBOUND_QUERY)
        assert "dns" in log.tags
        assert "unbound" in log.tags


class TestDnsmasqParser:
    def test_query_parsed(self):
        log = parse_dnsmasq_dns(DNSMASQ_QUERY)
        assert log is not None
        assert log.source_type == "dns_resolver"
        assert log.event_action == "dns_query"
        assert log.source_ip == "192.168.1.10"
        assert log.extra["query_domain"] == "evil.com"
        assert log.extra["query_type"] == "A"

    def test_unrelated_line_returns_none(self):
        assert parse_dnsmasq_dns("this is not dnsmasq") is None

    def test_tags(self):
        log = parse_dnsmasq_dns(DNSMASQ_QUERY)
        assert "dns" in log.tags
        assert "dnsmasq" in log.tags


class TestFortiGateDnsParser:
    def test_pass_parsed(self):
        log = parse_fortigate_dns(FORTI_DNS_PASS)
        assert log is not None
        assert log.source_type == "dns_resolver"
        assert log.event_action == "dns_query"
        assert log.source_ip == "192.168.1.20"
        assert log.destination_ip == "1.2.3.4"
        assert log.extra["query_domain"] == "evil.com"
        assert log.extra["response_ip"] == "1.2.3.4"
        assert log.severity == "info"

    def test_block_is_warning(self):
        log = parse_fortigate_dns(FORTI_DNS_BLOCK)
        assert log.severity == "warning"
        assert log.extra["action"] == "block"

    def test_non_dns_subtype_returns_none(self):
        assert parse_fortigate_dns(FORTI_DENY) is None

    def test_missing_qname_returns_none(self):
        line = FORTI_DNS_PASS.replace('qname="evil.com" ', '')
        assert parse_fortigate_dns(line) is None

    def test_tags(self):
        log = parse_fortigate_dns(FORTI_DNS_PASS)
        assert "dns" in log.tags
        assert "fortigate" in log.tags


class TestDnsResolverSyslogDispatcher:
    def test_dispatches_unbound(self):
        log = parse_dns_resolver_syslog(UNBOUND_QUERY)
        assert log is not None
        assert "unbound" in log.tags

    def test_dispatches_dnsmasq(self):
        log = parse_dns_resolver_syslog(DNSMASQ_QUERY)
        assert log is not None
        assert "dnsmasq" in log.tags

    def test_dispatches_fortigate(self):
        log = parse_dns_resolver_syslog(FORTI_DNS_PASS)
        assert log is not None
        assert "fortigate" in log.tags

    def test_unrelated_line_returns_none(self):
        assert parse_dns_resolver_syslog("this is not a dns log") is None

    def test_fortigate_traffic_log_not_misdetected_as_dns(self):
        """FortiGate'in normal trafik logu (type=traffic) DNS dispatcher'ı tetiklememeli."""
        assert parse_dns_resolver_syslog(FORTI_DENY) is None


class TestDetectAndParseDns:
    def test_detects_unbound(self):
        log = detect_and_parse(UNBOUND_QUERY)
        assert log is not None
        assert log.source_type == "dns_resolver"

    def test_detects_fortigate_dns_not_generic_fortigate(self):
        """type=utm subtype=dns hem FORTIGATE hem DNS pattern'ine uyar — DNS önce gelmeli."""
        log = detect_and_parse(FORTI_DNS_PASS)
        assert log is not None
        assert log.event_action == "dns_query"


# ── F3 — Firewall yönetim erişimi (marka bağımsız) ─────────────────────────

FORTI_ADMIN_OK = (
    'date=2026-06-16 time=10:00:01 devname="FG1" type="event" subtype="system" '
    'level="information" logdesc="Admin login successful" user="admin" '
    'ui="ssh(192.168.1.30)" method="ssh" srcip=192.168.1.30 dstip=10.0.0.1 '
    'action="login" status="success"'
)
FORTI_ADMIN_FAIL = (
    'date=2026-06-16 time=10:00:01 devname="FG1" type="event" subtype="system" '
    'logdesc="Admin login failed" user="admin" method="ssh" srcip=192.168.1.30 '
    'action="login" status="failed"'
)
ASA_LOGIN_PERMIT = (
    'Jun 06 2026 13:03:07: %ASA-6-605005: Login permitted from 10.10.10.10/60358 '
    'to inside:172.18.254.34/ssh for user "admin"'
)
ASA_LOGIN_DENY = (
    'Jun 06 2026 13:03:07: %ASA-6-605004: Login denied from 10.10.10.10/60358 '
    'to inside:172.18.254.34/ssh for user "admin"'
)
ASA_AUTH_OK = (
    'May 07 2026 12:57:26: %ASA-6-611101: User authentication succeeded: '
    'IP address: 10.65.81.163, Uname: admin'
)
ASA_AUTH_FAIL = (
    'May 07 2026 12:57:26: %ASA-6-611102: User authentication failed: '
    'IP address: 10.65.81.163, Uname: admin'
)
PFSENSE_LOGIN_OK = (
    "Apr 24 10:00:01 opnsense php-fpm[412]: /index.php: Successful login "
    "for user 'admin' from: 192.168.1.40 (Local Database)"
)
PFSENSE_LOGIN_FAIL = (
    "Apr 24 10:00:01 opnsense php-fpm[412]: /index.php: webConfigurator "
    "authentication error for user 'admin' from: 192.168.1.40"
)
VYOS_SSH_OK = "Apr 24 10:00:01 vyos sshd[5123]: Accepted publickey for vyos from 192.168.203.1 port 54321 ssh2"
VYOS_SSH_FAIL = "Apr 24 10:00:01 vyos sshd[5123]: Failed password for vyos from 192.168.203.1 port 54321 ssh2"


class TestFortiGateAdminAccess:
    def test_success_parsed(self):
        log = parse_fortigate_admin_access(FORTI_ADMIN_OK)
        assert log is not None
        assert log.event_action == "fw_admin_login_success"
        assert log.source_ip == "192.168.1.30"
        assert log.severity == "info"
        assert log.event_category == "authentication"

    def test_failure_parsed(self):
        log = parse_fortigate_admin_access(FORTI_ADMIN_FAIL)
        assert log.event_action == "fw_admin_login_failure"
        assert log.severity == "warning"

    def test_non_login_system_event_returns_none(self):
        line = FORTI_ADMIN_OK.replace('action="login"', 'action="config-change"')
        assert parse_fortigate_admin_access(line) is None

    def test_non_system_subtype_returns_none(self):
        assert parse_fortigate_admin_access(FORTI_DENY) is None

    def test_tags(self):
        log = parse_fortigate_admin_access(FORTI_ADMIN_OK)
        assert "fw_admin" in log.tags
        assert "fortigate" in log.tags


class TestCiscoAsaAdminAccess:
    def test_login_permitted(self):
        log = parse_cisco_asa_admin_access(ASA_LOGIN_PERMIT)
        assert log is not None
        assert log.event_action == "fw_admin_login_success"
        assert log.source_ip == "10.10.10.10"
        assert log.extra["user"] == "admin"

    def test_login_denied(self):
        log = parse_cisco_asa_admin_access(ASA_LOGIN_DENY)
        assert log.event_action == "fw_admin_login_failure"
        assert log.severity == "warning"

    def test_auth_succeeded(self):
        log = parse_cisco_asa_admin_access(ASA_AUTH_OK)
        assert log.event_action == "fw_admin_login_success"
        assert log.source_ip == "10.65.81.163"

    def test_auth_failed(self):
        log = parse_cisco_asa_admin_access(ASA_AUTH_FAIL)
        assert log.event_action == "fw_admin_login_failure"

    def test_unrelated_asa_code_returns_none(self):
        assert parse_cisco_asa_admin_access(ASA_DENY) is None

    def test_tags(self):
        log = parse_cisco_asa_admin_access(ASA_LOGIN_PERMIT)
        assert "fw_admin" in log.tags
        assert "cisco_asa" in log.tags


class TestPfsenseAdminAccess:
    def test_success_parsed(self):
        log = parse_pfsense_admin_access(PFSENSE_LOGIN_OK)
        assert log is not None
        assert log.event_action == "fw_admin_login_success"
        assert log.source_ip == "192.168.1.40"
        assert log.observer_hostname == "opnsense"

    def test_failure_parsed(self):
        log = parse_pfsense_admin_access(PFSENSE_LOGIN_FAIL)
        assert log.event_action == "fw_admin_login_failure"
        assert log.severity == "warning"

    def test_unrelated_line_returns_none(self):
        assert parse_pfsense_admin_access("php-fpm[1]: /index.php: something else") is None

    def test_tags(self):
        log = parse_pfsense_admin_access(PFSENSE_LOGIN_OK)
        assert "fw_admin" in log.tags
        assert "opnsense" in log.tags


class TestVyosAdminAccess:
    def test_success_parsed(self):
        log = parse_vyos_admin_access(VYOS_SSH_OK)
        assert log is not None
        assert log.event_action == "fw_admin_login_success"
        assert log.source_ip == "192.168.203.1"
        assert log.observer_hostname == "vyos"

    def test_failure_parsed(self):
        log = parse_vyos_admin_access(VYOS_SSH_FAIL)
        assert log.event_action == "fw_admin_login_failure"
        assert log.severity == "warning"

    def test_unrelated_line_returns_none(self):
        assert parse_vyos_admin_access("just some random text") is None

    def test_tags(self):
        log = parse_vyos_admin_access(VYOS_SSH_OK)
        assert "fw_admin" in log.tags
        assert "vyos" in log.tags


class TestFwAdminAccessDispatcher:
    def test_dispatches_fortigate(self):
        log = parse_fw_admin_access(FORTI_ADMIN_OK)
        assert log is not None and "fortigate" in log.tags

    def test_dispatches_asa(self):
        log = parse_fw_admin_access(ASA_LOGIN_PERMIT)
        assert log is not None and "cisco_asa" in log.tags

    def test_dispatches_pfsense(self):
        log = parse_fw_admin_access(PFSENSE_LOGIN_OK)
        assert log is not None and "opnsense" in log.tags

    def test_dispatches_vyos(self):
        log = parse_fw_admin_access(VYOS_SSH_OK)
        assert log is not None and "vyos" in log.tags

    def test_unrelated_line_returns_none(self):
        assert parse_fw_admin_access("this is not an admin access log") is None

    def test_does_not_swallow_regular_traffic_logs(self):
        """fw_admin dispatcher normal trafik/DHCP/DNS loglarını yutmamalı."""
        assert parse_fw_admin_access(FORTI_DENY) is None
        assert parse_fw_admin_access(ASA_DENY) is None


class TestDetectAndParseAdminAccess:
    def test_asa_admin_login_not_swallowed_by_generic_asa(self):
        """parse_cisco_asa() her %ASA- satırını yutar — admin access önce kontrol edilmeli."""
        log = detect_and_parse(ASA_LOGIN_PERMIT)
        assert log is not None
        assert log.event_action == "fw_admin_login_success"

    def test_fortigate_admin_not_swallowed_by_generic_fortigate(self):
        log = detect_and_parse(FORTI_ADMIN_OK)
        assert log is not None
        assert log.event_action == "fw_admin_login_success"

    def test_vyos_admin_detected(self):
        log = detect_and_parse(VYOS_SSH_OK)
        assert log is not None
        assert log.event_action == "fw_admin_login_success"

    def test_normal_asa_traffic_still_works(self):
        log = detect_and_parse(ASA_DENY)
        assert log is not None
        assert log.event_action == "fw_block"


class TestFwAdminStageMap:
    def test_login_failure_maps_to_weaponize(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("fw_admin_login_failure") == "weaponize"

    def test_login_success_maps_to_access(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("fw_admin_login_success") == "access"

    def test_brute_force_maps_to_weaponize(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("fw_admin_brute_force") == "weaponize"


class TestFwAdminBruteForceSigmaRule:
    def test_rule_loads_and_produces_expected_output_action(self):
        from server.sigma_executor import SigmaExecutor
        ex = SigmaExecutor()
        ex.load_dir()
        matches = [r for r in ex.rules if r.title == "FW Admin Brute Force"]
        assert len(matches) == 1
        rule = matches[0]
        assert rule.output_event_action == "fw_admin_brute_force_detected"
        assert rule.is_correlation is True
        assert rule.window_seconds == 300
        assert rule.group_by_fields == ["source_ip"]


# ──────────────────────────────────────────────────────────────────
# G1 — Multi-vendor router routing + interface event parser testleri
# ──────────────────────────────────────────────────────────────────

CISCO_BGP_DOWN = (
    "Jun 18 09:10:00 router1 %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down Neighbor deleted"
)
CISCO_BGP_UP = (
    "Jun 18 09:11:00 router1 %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Up"
)
CISCO_LINK_DOWN = (
    "Jun 18 09:12:00 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"
)
CISCO_LINK_UP = (
    "Jun 18 09:12:05 router1 %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up"
)
CISCO_LINEPROTO_DOWN = (
    "Jun 18 09:12:01 router1 %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1 changed state to down"
)
JUNIPER_BGP_DOWN = (
    "Jun 18 10:00:00 juniper1 rpd[1234]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 192.168.1.2 "
    "(External AS 64512) changed state from Established to Idle (event: RecvNotify) (instance master)"
)
JUNIPER_BGP_UP = (
    "Jun 18 10:01:00 juniper1 rpd[1234]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 192.168.1.2 "
    "(External AS 64512) changed state from Active to Established (event: RecvOpen) (instance master)"
)
JUNIPER_LINK_DOWN = (
    "Jun 18 10:02:00 juniper1 mib2d[5678]: SNMP_TRAP_LINK_DOWN: ifIndex 523, "
    "ifAdminStatus up(1), ifOperStatus down(2), ifName ge-0/0/0"
)
JUNIPER_LINK_UP = (
    "Jun 18 10:02:05 juniper1 mib2d[5678]: SNMP_TRAP_LINK_UP: ifIndex 523, "
    "ifAdminStatus up(1), ifOperStatus up(1), ifName ge-0/0/0"
)
MIKROTIK_IFACE_DOWN = (
    "Jun 18 11:00:00 mikrotik - - - interface,error sfp1 link down"
)
MIKROTIK_IFACE_UP = (
    "Jun 18 11:00:05 mikrotik - - - interface,info sfp1 link up"
)
FORTI_IFACE_DOWN = (
    'Jun 18 12:00:00 fortigate type=event subtype=system '
    'logdesc="Interface changed" action=link-down iface=port1'
)
FORTI_IFACE_UP = (
    'Jun 18 12:00:05 fortigate type=event subtype=system '
    'logdesc="Interface changed" action=link-up iface=port1'
)
VYOS_IFACE_DOWN = "Jun 18 08:00:00 vyos kernel: eth1: Link is Down"
VYOS_BGP_DOWN = "Jun 18 08:01:00 vyos bgpd[123]: BGP: peer 10.0.30.1 Down BGP Notification sent"
VYOS_OSPF_CHANGE = "Jun 18 08:02:00 vyos ospfd[456]: neighbor 192.168.1.10 state change Full"
VYOS_ROUTE_CHANGE = "Jun 18 08:03:00 vyos zebra[789]: route 0.0.0.0/0 added"


class TestCiscoIOSRouting:
    def test_bgp_down_action(self):
        log = parse_cisco_ios_routing(CISCO_BGP_DOWN)
        assert log is not None
        assert log.event_action == "bgp_state_change"

    def test_bgp_down_severity_warning(self):
        log = parse_cisco_ios_routing(CISCO_BGP_DOWN)
        assert log.severity == "warning"

    def test_bgp_down_peer_in_extra(self):
        log = parse_cisco_ios_routing(CISCO_BGP_DOWN)
        assert log.extra["peer"] == "10.0.0.1"
        assert log.extra["state"] == "down"

    def test_bgp_up_severity_info(self):
        log = parse_cisco_ios_routing(CISCO_BGP_UP)
        assert log.severity == "info"

    def test_bgp_source_type(self):
        from shared.models import LogSourceType
        log = parse_cisco_ios_routing(CISCO_BGP_DOWN)
        assert log.source_type == LogSourceType.CISCO_IOS

    def test_link_down_action(self):
        log = parse_cisco_ios_routing(CISCO_LINK_DOWN)
        assert log is not None
        assert log.event_action == "interface_link_down"

    def test_link_down_severity_warning(self):
        log = parse_cisco_ios_routing(CISCO_LINK_DOWN)
        assert log.severity == "warning"

    def test_link_up_action(self):
        log = parse_cisco_ios_routing(CISCO_LINK_UP)
        assert log.event_action == "interface_link_up"
        assert log.severity == "info"

    def test_lineproto_down(self):
        log = parse_cisco_ios_routing(CISCO_LINEPROTO_DOWN)
        assert log is not None
        assert log.event_action == "interface_link_down"

    def test_iface_in_extra(self):
        log = parse_cisco_ios_routing(CISCO_LINK_DOWN)
        assert "GigabitEthernet0/1" in log.extra["interface"]


class TestJuniperRouting:
    def test_bgp_down_action(self):
        log = parse_juniper_routing(JUNIPER_BGP_DOWN)
        assert log is not None
        assert log.event_action == "bgp_state_change"

    def test_bgp_down_severity(self):
        log = parse_juniper_routing(JUNIPER_BGP_DOWN)
        assert log.severity == "warning"

    def test_bgp_established_severity_info(self):
        log = parse_juniper_routing(JUNIPER_BGP_UP)
        assert log.severity == "info"

    def test_bgp_peer_extracted(self):
        log = parse_juniper_routing(JUNIPER_BGP_DOWN)
        assert log.extra["peer"] == "192.168.1.2"

    def test_link_down_action(self):
        log = parse_juniper_routing(JUNIPER_LINK_DOWN)
        assert log is not None
        assert log.event_action == "interface_link_down"

    def test_link_up_action(self):
        log = parse_juniper_routing(JUNIPER_LINK_UP)
        assert log.event_action == "interface_link_up"
        assert log.severity == "info"

    def test_iface_in_extra(self):
        log = parse_juniper_routing(JUNIPER_LINK_DOWN)
        assert log.extra["interface"] == "ge-0/0/0"

    def test_source_type(self):
        from shared.models import LogSourceType
        log = parse_juniper_routing(JUNIPER_BGP_DOWN)
        assert log.source_type == LogSourceType.JUNIPER


class TestMikrotikInterface:
    def test_down_action(self):
        log = parse_mikrotik_interface(MIKROTIK_IFACE_DOWN)
        assert log is not None
        assert log.event_action == "interface_link_down"

    def test_down_severity(self):
        log = parse_mikrotik_interface(MIKROTIK_IFACE_DOWN)
        assert log.severity == "warning"

    def test_up_action(self):
        log = parse_mikrotik_interface(MIKROTIK_IFACE_UP)
        assert log.event_action == "interface_link_up"
        assert log.severity == "info"

    def test_iface_in_extra(self):
        log = parse_mikrotik_interface(MIKROTIK_IFACE_DOWN)
        assert log.extra["interface"] == "sfp1"

    def test_source_type(self):
        from shared.models import LogSourceType
        log = parse_mikrotik_interface(MIKROTIK_IFACE_DOWN)
        assert log.source_type == LogSourceType.MIKROTIK

    def test_no_match_returns_none(self):
        log = parse_mikrotik_interface("Jun 18 11:00:00 mikrotik - random syslog line")
        assert log is None


class TestFortigateInterfaceEvent:
    def test_link_down_action(self):
        log = parse_fortigate_interface_event(FORTI_IFACE_DOWN)
        assert log is not None
        assert log.event_action == "interface_link_down"

    def test_link_up_action(self):
        log = parse_fortigate_interface_event(FORTI_IFACE_UP)
        assert log.event_action == "interface_link_up"

    def test_down_severity(self):
        log = parse_fortigate_interface_event(FORTI_IFACE_DOWN)
        assert log.severity == "warning"

    def test_iface_in_extra(self):
        log = parse_fortigate_interface_event(FORTI_IFACE_DOWN)
        assert log.extra["interface"] == "port1"

    def test_no_match_returns_none(self):
        log = parse_fortigate_interface_event(
            "Jun 18 type=event subtype=system action=login user=admin"
        )
        assert log is None


class TestVyosRoutingEvents:
    def test_iface_down(self):
        log = parse_vyos_routing_events(VYOS_IFACE_DOWN)
        assert log is not None
        assert log.event_action == "interface_link_down"
        assert log.severity == "critical"

    def test_bgp_event(self):
        log = parse_vyos_routing_events(VYOS_BGP_DOWN)
        assert log is not None
        assert log.event_action == "bgp_state_change"

    def test_ospf_event(self):
        log = parse_vyos_routing_events(VYOS_OSPF_CHANGE)
        assert log is not None
        assert log.event_action == "ospf_state_change"

    def test_route_change(self):
        log = parse_vyos_routing_events(VYOS_ROUTE_CHANGE)
        assert log is not None
        assert log.event_action == "route_change"

    def test_no_match_returns_none(self):
        log = parse_vyos_routing_events("Jun 18 08:00:00 vyos sshd[123]: session opened")
        assert log is None


class TestParseRouterEventDispatcher:
    def test_cisco_bgp_routed_correctly(self):
        from shared.models import LogSourceType
        log = parse_router_event(CISCO_BGP_DOWN)
        assert log is not None
        assert log.source_type == LogSourceType.CISCO_IOS

    def test_cisco_link_routed_correctly(self):
        from shared.models import LogSourceType
        log = parse_router_event(CISCO_LINK_DOWN)
        assert log.source_type == LogSourceType.CISCO_IOS

    def test_juniper_bgp_routed_correctly(self):
        from shared.models import LogSourceType
        log = parse_router_event(JUNIPER_BGP_DOWN)
        assert log.source_type == LogSourceType.JUNIPER

    def test_mikrotik_routed_correctly(self):
        from shared.models import LogSourceType
        log = parse_router_event(MIKROTIK_IFACE_DOWN)
        assert log.source_type == LogSourceType.MIKROTIK

    def test_vyos_routed_correctly(self):
        from shared.models import LogSourceType
        log = parse_router_event(VYOS_IFACE_DOWN)
        assert log.source_type == LogSourceType.VYOS

    def test_unrelated_line_returns_none(self):
        log = parse_router_event("Jun 18 08:00:00 host sshd[123]: session opened")
        assert log is None


class TestDetectAndParseRouterEvents:
    def test_cisco_bgp_detected(self):
        log = detect_and_parse(CISCO_BGP_DOWN)
        assert log is not None
        assert log.event_action == "bgp_state_change"

    def test_cisco_link_detected(self):
        log = detect_and_parse(CISCO_LINK_DOWN)
        assert log is not None
        assert log.event_action == "interface_link_down"

    def test_juniper_bgp_detected(self):
        log = detect_and_parse(JUNIPER_BGP_DOWN)
        assert log is not None
        assert log.event_action == "bgp_state_change"

    def test_mikrotik_iface_detected(self):
        log = detect_and_parse(MIKROTIK_IFACE_DOWN)
        assert log is not None
        assert log.event_action == "interface_link_down"

    def test_vyos_iface_detected(self):
        log = detect_and_parse(VYOS_IFACE_DOWN)
        assert log is not None
        assert log.event_action == "interface_link_down"


class TestRouterSigmaRules:
    def test_bgp_flapping_rule_loads(self):
        from server.sigma_executor import SigmaExecutor
        ex = SigmaExecutor()
        ex.load_dir()
        titles = [r.title for r in ex.rules]
        assert "BGP Peer Flapping" in titles

    def test_bgp_flapping_is_correlation(self):
        from server.sigma_executor import SigmaExecutor
        ex = SigmaExecutor()
        ex.load_dir()
        rule = next(r for r in ex.rules if r.title == "BGP Peer Flapping")
        assert rule.is_correlation is True
        assert rule.window_seconds == 300
        assert rule.group_by_fields == ["observer_hostname"]

    def test_iface_flapping_rule_loads(self):
        from server.sigma_executor import SigmaExecutor
        ex = SigmaExecutor()
        ex.load_dir()
        titles = [r.title for r in ex.rules]
        assert "Interface Flapping" in titles

    def test_iface_flapping_is_correlation(self):
        from server.sigma_executor import SigmaExecutor
        ex = SigmaExecutor()
        ex.load_dir()
        rule = next(r for r in ex.rules if r.title == "Interface Flapping")
        assert rule.is_correlation is True
        assert rule.window_seconds == 120
        assert rule.group_by_fields == ["observer_hostname"]


class TestRouterLogNormalizerSourcePatterns:
    def test_cisco_ios_bgp_identified(self):
        from server.log_normalizer import identify_source
        from shared.models import LogSourceType
        assert identify_source(CISCO_BGP_DOWN) == LogSourceType.CISCO_IOS

    def test_cisco_ios_link_identified(self):
        from server.log_normalizer import identify_source
        from shared.models import LogSourceType
        assert identify_source(CISCO_LINK_DOWN) == LogSourceType.CISCO_IOS

    def test_juniper_bgp_identified(self):
        from server.log_normalizer import identify_source
        from shared.models import LogSourceType
        assert identify_source(JUNIPER_BGP_DOWN) == LogSourceType.JUNIPER

    def test_mikrotik_iface_identified(self):
        from server.log_normalizer import identify_source
        from shared.models import LogSourceType
        assert identify_source(MIKROTIK_IFACE_DOWN) == LogSourceType.MIKROTIK
