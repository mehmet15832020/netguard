"""
Community ID cross-source korelasyon testleri — C1 NSM.

Zeek conn/dns/http/ssl/ssh, Suricata alert/flow, NetFlow v5/v9,
IPFIX, sFlow parser'larında community_id alanı dolu olmalı.
DB metodu ve route da test edilir.
"""

import struct
import socket
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from server.main import app

client = TestClient(app)


# ─── Yardımcı ────────────────────────────────────────────────────────────────

def _ts():
    return datetime.now(timezone.utc).isoformat()


# ─── Zeek parser'lar ─────────────────────────────────────────────────────────

class TestZeekCommunityId:
    CID = "1:K2Z9rgZl/kbRXxTe32amzRohiJo="

    def _base(self):
        return {
            "ts": _ts(),
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 54321,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 80,
            "community_id": self.CID,
        }

    def test_parse_dns_community_id(self):
        from server.parsers.zeek import parse_dns
        row = {**self._base(), "proto": "udp", "query": "example.com", "qtype_name": "A", "id.resp_p": 53}
        log = parse_dns(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_dns_missing_community_id(self):
        from server.parsers.zeek import parse_dns
        row = {**self._base(), "proto": "udp", "query": "example.com", "id.resp_p": 53}
        del row["community_id"]
        log = parse_dns(row)
        assert log is not None
        assert log.community_id is None

    def test_parse_http_community_id(self):
        from server.parsers.zeek import parse_http
        row = {**self._base(), "method": "GET", "host": "example.com", "uri": "/", "status_code": 200}
        log = parse_http(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_conn_community_id(self):
        from server.parsers.zeek import parse_conn
        row = {**self._base(), "conn_state": "SF", "duration": 10.0,
               "orig_bytes": 100, "resp_bytes": 200, "proto": "tcp"}
        log = parse_conn(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_ssh_community_id(self):
        from server.parsers.zeek import parse_ssh
        row = {**self._base(), "auth_success": False, "auth_attempts": 3}
        log = parse_ssh(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_ssl_community_id(self):
        from server.parsers.zeek import parse_ssl
        row = {**self._base(), "id.resp_p": 443, "server_name": "example.com",
               "validation_status": "ok", "subject": "CN=example.com"}
        log = parse_ssl(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_notice_community_id(self):
        from server.parsers.zeek import parse_notice
        row = {**self._base(), "note": "Scan::Port_Scan", "msg": "port scan detected"}
        log = parse_notice(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_smtp_community_id(self):
        from server.parsers.zeek import parse_smtp
        row = {**self._base(), "mailfrom": "a@b.com", "rcptto": ["c@d.com"], "subject": "test"}
        log = parse_smtp(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_weird_community_id(self):
        from server.parsers.zeek import parse_weird
        row = {**self._base(), "name": "bad_HTTP_request", "proto": "tcp",
               "id.orig_h": "1.2.3.4", "id.resp_h": "8.8.8.8"}
        log = parse_weird(row)
        assert log is not None
        assert log.community_id == self.CID


# ─── Suricata parser'lar ─────────────────────────────────────────────────────

class TestSuricataCommunityId:
    CID = "1:EkNmRpdbECIu1ZyS/TmfXkaDF1w="

    def _base(self):
        return {
            "timestamp": _ts(),
            "src_ip": "192.168.1.10",
            "src_port": 54321,
            "dest_ip": "10.0.0.1",
            "dest_port": 80,
            "proto": "TCP",
            "community_id": self.CID,
        }

    def test_parse_alert_community_id(self):
        from server.parsers.suricata import parse_alert
        row = {**self._base(), "alert": {"signature": "Test alert", "severity": 2, "signature_id": "1234"}}
        log = parse_alert(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_dns_community_id(self):
        from server.parsers.suricata import parse_dns
        row = {**self._base(), "proto": "UDP", "dest_port": 53,
               "dns": {"rrname": "example.com", "rrtype": "A", "type": "query"}}
        log = parse_dns(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_http_community_id(self):
        from server.parsers.suricata import parse_http
        row = {**self._base(), "http": {"hostname": "example.com", "url": "/", "http_method": "GET", "status": 200}}
        log = parse_http(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_tls_community_id(self):
        from server.parsers.suricata import parse_tls
        row = {**self._base(), "dest_port": 443,
               "tls": {"sni": "example.com", "version": "TLSv1.3"}}
        log = parse_tls(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_flow_community_id(self):
        from server.parsers.suricata import parse_flow
        row = {**self._base(), "flow": {"state": "closed", "bytes_toserver": 100, "bytes_toclient": 200,
                                        "pkts_toserver": 5, "pkts_toclient": 8}}
        log = parse_flow(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_ssh_community_id(self):
        from server.parsers.suricata import parse_ssh
        row = {**self._base(), "dest_port": 22,
               "ssh": {"client": {"software_version": "OpenSSH_8.0", "proto_version": "2.0"},
                       "server": {"software_version": "OpenSSH_9.0"}}}
        log = parse_ssh(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_parse_anomaly_community_id(self):
        from server.parsers.suricata import parse_anomaly
        row = {**self._base(), "anomaly": {"type": "applayer", "event": "INVALID_RECORD_TYPE", "layer": "proto"}}
        log = parse_anomaly(row)
        assert log is not None
        assert log.community_id == self.CID

    def test_missing_community_id_is_none(self):
        from server.parsers.suricata import parse_alert
        row = {**self._base(), "alert": {"signature": "Test", "severity": 2, "signature_id": "1"}}
        del row["community_id"]
        log = parse_alert(row)
        assert log is not None
        assert log.community_id is None


# ─── NetFlow parser'lar ───────────────────────────────────────────────────────

class TestNetflowCommunityId:

    def test_parse_v5_has_community_id(self):
        from server.parsers.netflow import parse_v5
        # Build minimal NetFlow v5 packet
        count = 1
        header = struct.pack("!HHIIIIBBH",
            5, count,             # version H, count H
            0, 1000000, 0, 0,     # uptime I, unix_secs I, unix_nsecs I, flow_seq I
            0, 0,                 # engine_type B, engine_id B
            0)                    # sampling H
        src_ip = socket.inet_aton("192.168.1.10")
        dst_ip = socket.inet_aton("10.0.0.1")
        record = struct.pack("!IIIHHIIIIHHBBBBHHBBxx",
            int.from_bytes(src_ip, "big"),
            int.from_bytes(dst_ip, "big"),
            0,             # nexthop
            0, 0,          # input/output interface
            10, 5000,      # packets, octets
            0, 0,          # first, last sysuptime
            54321, 80,     # src_port, dst_port
            0,             # pad1
            0x18,          # tcp_flags
            6,             # protocol (TCP)
            0,             # tos
            0, 0,          # src_as, dst_as
            24, 8,         # src_mask, dst_mask
        )
        data = header + record
        logs = parse_v5(data, "router1")
        assert len(logs) == 1
        assert logs[0].community_id is not None
        assert logs[0].community_id.startswith("1:")

    def test_community_id_helper_tcp(self):
        from server.parsers.netflow import _community_id
        result = _community_id(6, "192.168.1.10", "10.0.0.1", 54321, 80)
        assert result is not None
        assert result.startswith("1:")

    def test_community_id_helper_udp(self):
        from server.parsers.netflow import _community_id
        result = _community_id(17, "192.168.1.10", "8.8.8.8", 54321, 53)
        assert result is not None
        assert result.startswith("1:")

    def test_community_id_helper_invalid_ip(self):
        from server.parsers.netflow import _community_id
        result = _community_id(6, "not-an-ip", "10.0.0.1", 1234, 80)
        assert result is None

    def test_community_id_symmetric(self):
        """Aynı 5-tuple her zaman aynı community_id üretmeli."""
        from server.parsers.netflow import _community_id
        a = _community_id(6, "192.168.1.10", "10.0.0.1", 54321, 80)
        b = _community_id(6, "192.168.1.10", "10.0.0.1", 54321, 80)
        assert a == b
        assert a is not None


# ─── NormalizedLog modeli ─────────────────────────────────────────────────────

class TestNormalizedLogModel:
    def test_community_id_field_optional(self):
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        log = NormalizedLog(
            log_id="test-1",
            raw_id="raw-1",
            source_type=LogSourceType.ZEEK,
            observer_hostname="zeek",
            timestamp=datetime.now(timezone.utc),
            severity="info",
            event_category=LogCategory.NETWORK,
            event_action="test",
            message="test",
        )
        assert log.community_id is None

    def test_community_id_field_set(self):
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        cid = "1:K2Z9rgZl/kbRXxTe32amzRohiJo="
        log = NormalizedLog(
            log_id="test-2",
            raw_id="raw-2",
            source_type=LogSourceType.ZEEK,
            observer_hostname="zeek",
            timestamp=datetime.now(timezone.utc),
            severity="info",
            event_category=LogCategory.NETWORK,
            event_action="test",
            message="test",
            community_id=cid,
        )
        assert log.community_id == cid


# ─── Route testi ─────────────────────────────────────────────────────────────

class TestCommunityIdRoute:
    CID = "1:K2Z9rgZl/kbRXxTe32amzRohiJo="

    def test_get_by_community_id_valid(self, admin_token):
        with patch("server.routes.logs.db") as mock_db:
            mock_db.get_logs_by_community_id.return_value = [
                {"log_id": "abc", "source_type": "ZEEK", "community_id": self.CID,
                 "message": "test", "timestamp": _ts()}
            ]
            resp = client.get(
                f"/api/v1/logs/by-community-id/{self.CID}?hours=24",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["community_id"] == self.CID
        assert data["count"] == 1

    def test_get_by_community_id_invalid_format(self, admin_token):
        resp = client.get(
            "/api/v1/logs/by-community-id/not-valid-format?hours=24",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 400

    def test_get_by_community_id_empty(self, admin_token):
        with patch("server.routes.logs.db") as mock_db:
            mock_db.get_logs_by_community_id.return_value = []
            resp = client.get(
                f"/api/v1/logs/by-community-id/{self.CID}",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_get_by_community_id_requires_auth(self):
        resp = client.get(f"/api/v1/logs/by-community-id/{self.CID}")
        assert resp.status_code == 401

    def test_hours_param_out_of_range(self, admin_token):
        resp = client.get(
            f"/api/v1/logs/by-community-id/{self.CID}?hours=999",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 422


# ─── DB metodu testi ─────────────────────────────────────────────────────────

class TestDatabaseGetByCommunityId:
    CID = "1:K2Z9rgZl/kbRXxTe32amzRohiJo="

    def test_get_logs_by_community_id_empty(self, tmp_db):
        results = tmp_db.get_logs_by_community_id(self.CID, tenant_id="default", hours=24)
        assert isinstance(results, list)
        assert len(results) == 0

    def test_get_logs_by_community_id_returns_matching(self, tmp_db):
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        log = NormalizedLog(
            log_id="cid-test-1",
            raw_id="raw-1",
            source_type=LogSourceType.ZEEK,
            observer_hostname="zeek",
            timestamp=datetime.now(timezone.utc),
            severity="info",
            event_category=LogCategory.NETWORK,
            event_action="network_connection",
            message="test connection",
            community_id=self.CID,
        )
        tmp_db.save_normalized_log(log, tenant_id="default")
        results = tmp_db.get_logs_by_community_id(self.CID, tenant_id="default", hours=1)
        assert len(results) == 1
        assert results[0]["community_id"] == self.CID
        assert results[0]["source_type"] == "zeek"

    def test_get_logs_by_community_id_tenant_isolation(self, tmp_db):
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        log = NormalizedLog(
            log_id="cid-test-2",
            raw_id="raw-2",
            source_type=LogSourceType.SURICATA,
            observer_hostname="suricata",
            timestamp=datetime.now(timezone.utc),
            severity="warning",
            event_category=LogCategory.INTRUSION,
            event_action="suricata_alert",
            message="test alert",
            community_id=self.CID,
        )
        tmp_db.save_normalized_log(log, tenant_id="other_tenant")
        results = tmp_db.get_logs_by_community_id(self.CID, tenant_id="default", hours=1)
        assert all(r.get("community_id") == self.CID for r in results)
        # other_tenant'a ait kayıt default tenant'ta görünmemeli
        for r in results:
            assert r.get("log_id") != "cid-test-2"

    def test_get_logs_by_community_id_null_not_returned(self, tmp_db):
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        log = NormalizedLog(
            log_id="no-cid-1",
            raw_id="raw-3",
            source_type=LogSourceType.ZEEK,
            observer_hostname="zeek",
            timestamp=datetime.now(timezone.utc),
            severity="info",
            event_category=LogCategory.NETWORK,
            event_action="test",
            message="no community id",
            community_id=None,
        )
        tmp_db.save_normalized_log(log, tenant_id="default")
        results = tmp_db.get_logs_by_community_id(self.CID, tenant_id="default", hours=1)
        for r in results:
            assert r["log_id"] != "no-cid-1"
