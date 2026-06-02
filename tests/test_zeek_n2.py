"""Zeek N2 parser testleri: weird.log, dpd.log, files.log"""
import pytest
from server.parsers.zeek import parse_weird, parse_dpd, parse_files

_BASE_TS = 1700000000.0


# ─────────────────────────────────────────────────────────── parse_weird ────

class TestParseWeird:

    def _row(self, name, src="1.2.3.4", dst="5.6.7.8", notice=False, addl=""):
        return {
            "ts": _BASE_TS,
            "name": name,
            "id.orig_h": src,
            "id.resp_h": dst,
            "id.orig_p": 12345,
            "id.resp_p": 80,
            "proto": "tcp",
            "notice": notice,
            "addl": addl,
        }

    def test_unknown_protocol_parsed(self):
        r = parse_weird(self._row("unknown_protocol"))
        assert r is not None
        assert r.event_action == "zeek_weird_unknown_protocol"
        assert r.severity == "warning"

    def test_notice_true_is_critical(self):
        r = parse_weird(self._row("unknown_protocol", notice=True))
        assert r is not None
        assert r.severity == "critical"

    def test_notice_string_T_is_critical(self):
        row = self._row("bad_HTTP_request")
        row["notice"] = "T"
        r = parse_weird(row)
        assert r is not None
        assert r.severity == "critical"

    def test_bad_http_request_parsed(self):
        r = parse_weird(self._row("bad_HTTP_request"))
        assert r is not None
        assert r.event_action == "zeek_weird_bad_http_request"

    def test_empty_name_returns_none(self):
        row = self._row("")
        assert parse_weird(row) is None

    def test_dash_name_returns_none(self):
        row = self._row("-")
        assert parse_weird(row) is None

    def test_ignored_weird_internal_skipped(self):
        r = parse_weird(self._row("window_recision",
                                  src="192.168.1.10",
                                  dst="192.168.1.20"))
        assert r is None

    def test_ignored_weird_external_not_skipped(self):
        r = parse_weird(self._row("window_recision",
                                  src="8.8.8.8",
                                  dst="192.168.1.20"))
        assert r is not None

    def test_addl_included_in_message(self):
        r = parse_weird(self._row("bad_HTTP_request", addl="extra info"))
        assert r is not None
        assert "extra info" in r.message

    def test_addl_dash_not_in_message(self):
        r = parse_weird(self._row("bad_HTTP_request", addl="-"))
        assert r is not None
        assert "-" not in r.message.split("[")[1:]

    def test_event_action_slug_format(self):
        r = parse_weird(self._row("TCP_seq_underflow"))
        assert r is not None
        assert r.event_action == "zeek_weird_tcp_seq_underflow"

    def test_source_destination_ip_populated(self):
        r = parse_weird(self._row("unknown_protocol", src="10.0.0.1", dst="8.8.8.8"))
        assert r is not None
        assert r.source_ip == "10.0.0.1"
        assert r.destination_ip == "8.8.8.8"

    def test_tags_include_zeek_weird(self):
        r = parse_weird(self._row("bad_HTTP_request"))
        assert r is not None
        assert "zeek" in r.tags
        assert "weird" in r.tags

    def test_non_ignored_internal_weird_parsed(self):
        r = parse_weird(self._row("truncated_IP",
                                  src="192.168.1.1",
                                  dst="192.168.1.2"))
        assert r is not None


# ─────────────────────────────────────────────────────────── parse_dpd ────

class TestParseDpd:

    def _row(self, analyzer, resp_p=80, proto="tcp", failure_reason=""):
        return {
            "ts": _BASE_TS,
            "analyzer": analyzer,
            "id.orig_h": "10.0.0.5",
            "id.orig_p": 54321,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": resp_p,
            "proto": proto,
            "failure_reason": failure_reason,
        }

    def test_ssl_on_443_is_critical(self):
        r = parse_dpd(self._row("SSL", resp_p=443, failure_reason="not a TLS ClientHello"))
        assert r is not None
        assert r.event_action == "zeek_dpd_ssl_failure"
        assert r.severity == "critical"

    def test_http_on_443_is_critical(self):
        r = parse_dpd(self._row("HTTP", resp_p=443))
        assert r is not None
        assert r.severity == "critical"

    def test_ssl_on_suspicious_port_is_critical(self):
        r = parse_dpd(self._row("SSL", resp_p=8080))
        assert r is not None
        assert r.severity == "critical"

    def test_ssl_on_non_suspicious_port_is_warning(self):
        r = parse_dpd(self._row("SSL", resp_p=12345))
        assert r is not None
        assert r.severity == "warning"

    def test_empty_analyzer_returns_none(self):
        assert parse_dpd(self._row("")) is None

    def test_dash_analyzer_returns_none(self):
        assert parse_dpd(self._row("-")) is None

    def test_failure_reason_in_message(self):
        r = parse_dpd(self._row("SSL", resp_p=443,
                                failure_reason="not a TLS ClientHello"))
        assert r is not None
        assert "not a TLS ClientHello" in r.message

    def test_failure_reason_dash_not_in_message(self):
        r = parse_dpd(self._row("HTTP", resp_p=443, failure_reason="-"))
        assert r is not None
        assert "failure_reason" not in r.message

    def test_event_action_format(self):
        r = parse_dpd(self._row("DNS", resp_p=53))
        assert r is not None
        assert r.event_action == "zeek_dpd_dns_failure"

    def test_destination_port_populated(self):
        r = parse_dpd(self._row("SSL", resp_p=443))
        assert r is not None
        assert r.destination_port == 443

    def test_dns_on_suspicious_port(self):
        r = parse_dpd(self._row("DNS", resp_p=443))
        assert r is not None
        assert r.severity == "critical"

    def test_tags_include_zeek_dpd(self):
        r = parse_dpd(self._row("SSL", resp_p=443))
        assert r is not None
        assert "zeek" in r.tags
        assert "dpd" in r.tags


# ─────────────────────────────────────────────────────────── parse_files ────

class TestParseFiles:

    def _row(self, mime_type="application/pdf", sha256="abc123def456" * 4,
             filename="doc.pdf", local_orig=True, is_orig=False,
             missing_bytes=0, tx_hosts=None, rx_hosts=None):
        return {
            "ts": _BASE_TS,
            "mime_type": mime_type,
            "filename": filename,
            "sha256": sha256,
            "sha1": "",
            "md5": "",
            "local_orig": local_orig,
            "is_orig": is_orig,
            "missing_bytes": missing_bytes,
            "tx_hosts": tx_hosts or ["8.8.8.8"],
            "rx_hosts": rx_hosts or ["192.168.1.10"],
        }

    def test_no_hash_returns_none(self):
        row = self._row()
        row["sha256"] = ""
        row["sha1"] = ""
        row["md5"] = ""
        assert parse_files(row) is None

    def test_missing_bytes_returns_none(self):
        assert parse_files(self._row(missing_bytes=1024)) is None

    def test_not_local_orig_returns_none(self):
        assert parse_files(self._row(local_orig=False)) is None

    def test_inbound_suspicious_mime_critical(self):
        r = parse_files(self._row(mime_type="application/x-dosexec", is_orig=False))
        assert r is not None
        assert r.event_action == "zeek_file_inbound_suspicious"
        assert r.severity == "critical"

    def test_inbound_normal_mime_warning(self):
        r = parse_files(self._row(mime_type="application/pdf", is_orig=False))
        assert r is not None
        assert r.event_action == "zeek_file_inbound"
        assert r.severity == "warning"

    def test_outbound_always_critical(self):
        r = parse_files(self._row(mime_type="application/pdf", is_orig=True))
        assert r is not None
        assert r.event_action == "zeek_file_outbound"
        assert r.severity == "critical"

    def test_outbound_suspicious_mime_critical(self):
        r = parse_files(self._row(mime_type="application/x-elf", is_orig=True))
        assert r is not None
        assert r.event_action == "zeek_file_outbound_suspicious"
        assert r.severity == "critical"

    def test_hash_in_extra(self):
        r = parse_files(self._row(sha256="a" * 48))
        assert r is not None
        assert r.extra.get("sha256") == "a" * 48

    def test_mime_type_in_extra(self):
        r = parse_files(self._row(mime_type="application/x-dosexec"))
        assert r is not None
        assert r.extra.get("mime_type") == "application/x-dosexec"

    def test_filename_in_message(self):
        r = parse_files(self._row(filename="malware.exe"))
        assert r is not None
        assert "malware.exe" in r.message

    def test_source_ip_from_tx_hosts(self):
        r = parse_files(self._row(tx_hosts=["1.2.3.4"], rx_hosts=["10.0.0.1"]))
        assert r is not None
        assert r.source_ip == "1.2.3.4"

    def test_dest_ip_from_rx_hosts(self):
        r = parse_files(self._row(tx_hosts=["1.2.3.4"], rx_hosts=["10.0.0.1"]))
        assert r is not None
        assert r.destination_ip == "10.0.0.1"

    def test_tx_hosts_string_format(self):
        row = self._row()
        row["tx_hosts"] = "1.2.3.4"
        row["rx_hosts"] = "10.0.0.1"
        r = parse_files(row)
        assert r is not None
        assert r.source_ip == "1.2.3.4"

    def test_missing_sha256_but_md5_present(self):
        row = self._row()
        row["sha256"] = ""
        row["md5"] = "d41d8cd98f00b204e9800998ecf8427e"
        r = parse_files(row)
        assert r is not None

    def test_powershell_mime_suspicious(self):
        r = parse_files(self._row(mime_type="application/x-powershell"))
        assert r is not None
        assert r.event_action.endswith("_suspicious")

    def test_tags_include_zeek_files(self):
        r = parse_files(self._row())
        assert r is not None
        assert "zeek" in r.tags
        assert "files" in r.tags

    def test_local_orig_false_returns_none(self):
        r = parse_files(self._row(local_orig=False))
        assert r is None


# ─────────────────────────────────────────────── zeek_collector integration ──

class TestZeekCollectorParsers:

    def test_weird_in_parsers(self):
        from server.zeek_collector import _PARSERS
        assert "weird" in _PARSERS

    def test_dpd_in_parsers(self):
        from server.zeek_collector import _PARSERS
        assert "dpd" in _PARSERS

    def test_files_in_parsers(self):
        from server.zeek_collector import _PARSERS
        assert "files" in _PARSERS

    def test_parsers_callable(self):
        from server.zeek_collector import _PARSERS
        from server.parsers.zeek import parse_weird, parse_dpd, parse_files
        assert _PARSERS["weird"] is parse_weird
        assert _PARSERS["dpd"] is parse_dpd
        assert _PARSERS["files"] is parse_files


# ─────────────────────────────────────────────── attack_chain STAGE_MAP ──

class TestStageMap:

    def test_weird_stage_map(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_weird_unknown_protocol") == "lateral"
        assert STAGE_MAP.get("zeek_weird_bad_http_request") == "execute"
        assert STAGE_MAP.get("zeek_weird_tcp_evasion") == "recon"

    def test_dpd_stage_map(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_dpd_ssl_failure") == "lateral"
        assert STAGE_MAP.get("zeek_dpd_http_failure") == "lateral"
        assert STAGE_MAP.get("zeek_dpd_dns_failure") == "lateral"

    def test_files_stage_map(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP.get("zeek_file_inbound_suspicious") == "execute"
        assert STAGE_MAP.get("zeek_file_outbound_suspicious") == "lateral"
        assert STAGE_MAP.get("zeek_file_inbound") == "execute"
        assert STAGE_MAP.get("zeek_file_outbound") == "lateral"
