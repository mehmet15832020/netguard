"""
D2 — network_bytes field Zeek + Suricata parser testleri.
Kapsam: her parser için populated / None / sıfır senaryoları.
"""

from server.parsers import zeek, suricata


# ── Zeek conn ────────────────────────────────────────────────────────────────

class TestZeekConnNetworkBytes:
    BASE = {
        "ts": 1_700_000_000,
        "conn_state": "SF",
        "duration": 5.0,
        "id.orig_h": "10.0.0.1",
        "id.resp_h": "10.0.0.2",
        "id.orig_p": 12345,
        "id.resp_p": 80,
        "proto": "tcp",
    }

    def test_orig_and_resp_bytes_summed(self):
        row = {**self.BASE, "orig_bytes": 1000, "resp_bytes": 2000}
        log = zeek.parse_conn(row)
        assert log is not None
        assert log.network_bytes == 3000

    def test_only_orig_bytes(self):
        row = {**self.BASE, "orig_bytes": 500, "resp_bytes": 0}
        log = zeek.parse_conn(row)
        assert log.network_bytes == 500

    def test_both_zero_returns_none(self):
        row = {**self.BASE, "orig_bytes": 0, "resp_bytes": 0}
        log = zeek.parse_conn(row)
        assert log.network_bytes is None

    def test_missing_fields_returns_none(self):
        log = zeek.parse_conn(self.BASE)
        assert log.network_bytes is None

    def test_string_bytes_parsed(self):
        row = {**self.BASE, "orig_bytes": "300", "resp_bytes": "700"}
        log = zeek.parse_conn(row)
        assert log.network_bytes == 1000

    def test_invalid_bytes_returns_none(self):
        row = {**self.BASE, "orig_bytes": "bad", "resp_bytes": "data"}
        log = zeek.parse_conn(row)
        assert log.network_bytes is None


# ── Zeek http ────────────────────────────────────────────────────────────────

class TestZeekHttpNetworkBytes:
    BASE = {
        "ts": 1_700_000_000,
        "id.orig_h": "10.0.0.1",
        "id.resp_h": "10.0.0.2",
        "id.orig_p": 54321,
        "id.resp_p": 80,
        "method": "GET",
        "uri": "/index.html",
        "host": "example.com",
        "status_code": 200,
    }

    def test_response_body_len_populated(self):
        row = {**self.BASE, "response_body_len": 4096}
        log = zeek.parse_http(row)
        assert log is not None
        assert log.network_bytes == 4096

    def test_zero_response_body_len_returns_none(self):
        row = {**self.BASE, "response_body_len": 0}
        log = zeek.parse_http(row)
        assert log.network_bytes is None

    def test_missing_response_body_len_returns_none(self):
        log = zeek.parse_http(self.BASE)
        assert log.network_bytes is None

    def test_string_body_len_parsed(self):
        row = {**self.BASE, "response_body_len": "8192"}
        log = zeek.parse_http(row)
        assert log.network_bytes == 8192


# ── Suricata flow ─────────────────────────────────────────────────────────────

class TestSuricataFlowNetworkBytes:
    BASE = {
        "timestamp": "2024-01-01T00:00:00Z",
        "src_ip": "10.0.0.1",
        "dest_ip": "10.0.0.2",
        "src_port": 12345,
        "dest_port": 80,
        "proto": "TCP",
    }

    def test_bytes_toserver_and_toclient_summed(self):
        row = {**self.BASE, "flow": {
            "bytes_toserver": 1500, "bytes_toclient": 3500,
            "pkts_toserver": 10, "pkts_toclient": 20,
        }}
        log = suricata.parse_flow(row)
        assert log is not None
        assert log.network_bytes == 5000

    def test_only_toserver_bytes(self):
        row = {**self.BASE, "flow": {
            "bytes_toserver": 800, "bytes_toclient": 0,
            "pkts_toserver": 5, "pkts_toclient": 0,
        }}
        log = suricata.parse_flow(row)
        assert log.network_bytes == 800

    def test_both_zero_returns_none(self):
        row = {**self.BASE, "flow": {
            "bytes_toserver": 0, "bytes_toclient": 0,
            "pkts_toserver": 0, "pkts_toclient": 0,
        }}
        log = suricata.parse_flow(row)
        assert log.network_bytes is None

    def test_missing_flow_block_returns_none(self):
        log = suricata.parse_flow({**self.BASE, "flow": {}})
        assert log is None


# ── Suricata http ─────────────────────────────────────────────────────────────

class TestSuricataHttpNetworkBytes:
    BASE = {
        "timestamp": "2024-01-01T00:00:00Z",
        "src_ip": "10.0.0.1",
        "dest_ip": "10.0.0.2",
        "src_port": 54321,
        "dest_port": 80,
        "proto": "TCP",
    }

    def test_length_field_populated(self):
        row = {**self.BASE, "http": {
            "hostname": "example.com",
            "url": "/",
            "http_method": "GET",
            "status": 200,
            "length": 2048,
            "http_user_agent": "Mozilla/5.0",
        }}
        log = suricata.parse_http(row)
        assert log is not None
        assert log.network_bytes == 2048

    def test_zero_length_returns_none(self):
        row = {**self.BASE, "http": {
            "hostname": "example.com",
            "url": "/",
            "http_method": "GET",
            "status": 200,
            "length": 0,
            "http_user_agent": "Mozilla/5.0",
        }}
        log = suricata.parse_http(row)
        assert log.network_bytes is None

    def test_missing_length_returns_none(self):
        row = {**self.BASE, "http": {
            "hostname": "example.com",
            "url": "/",
            "http_method": "GET",
            "status": 200,
            "http_user_agent": "Mozilla/5.0",
        }}
        log = suricata.parse_http(row)
        assert log.network_bytes is None

    def test_string_length_parsed(self):
        row = {**self.BASE, "http": {
            "hostname": "example.com",
            "url": "/",
            "http_method": "GET",
            "status": 200,
            "length": "512",
            "http_user_agent": "Mozilla/5.0",
        }}
        log = suricata.parse_http(row)
        assert log.network_bytes == 512


# ── Suricata fileinfo ─────────────────────────────────────────────────────────

class TestSuricataFileinfoNetworkBytes:
    BASE = {
        "timestamp": "2024-01-01T00:00:00Z",
        "src_ip": "10.0.0.1",
        "dest_ip": "10.0.0.2",
        "src_port": 54321,
        "dest_port": 80,
        "proto": "TCP",
    }

    def test_size_field_populated(self):
        row = {**self.BASE, "fileinfo": {
            "filename": "malware.exe",
            "size": 102400,
            "state": "CLOSED",
        }}
        log = suricata.parse_fileinfo(row)
        assert log is not None
        assert log.network_bytes == 102400

    def test_zero_size_returns_none(self):
        row = {**self.BASE, "fileinfo": {
            "filename": "empty.bin",
            "size": 0,
            "state": "CLOSED",
        }}
        log = suricata.parse_fileinfo(row)
        assert log.network_bytes is None

    def test_missing_size_returns_none(self):
        row = {**self.BASE, "fileinfo": {
            "filename": "unknown",
            "state": "CLOSED",
        }}
        log = suricata.parse_fileinfo(row)
        assert log.network_bytes is None

    def test_string_size_parsed(self):
        row = {**self.BASE, "fileinfo": {
            "filename": "document.pdf",
            "size": "65536",
            "state": "CLOSED",
        }}
        log = suricata.parse_fileinfo(row)
        assert log.network_bytes == 65536

    def test_large_file_size(self):
        row = {**self.BASE, "fileinfo": {
            "filename": "backup.tar.gz",
            "size": 500 * 1024 * 1024,
            "state": "CLOSED",
        }}
        log = suricata.parse_fileinfo(row)
        assert log.network_bytes == 500 * 1024 * 1024
