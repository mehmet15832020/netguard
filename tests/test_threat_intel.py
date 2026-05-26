"""Threat Intelligence modül testleri."""

from unittest.mock import patch, MagicMock
import json


class TestThreatIntelLookup:
    def test_private_ip_returns_none(self, tmp_db):
        from server.threat_intel import lookup
        assert lookup("192.168.1.1") is None
        assert lookup("10.0.0.1") is None
        assert lookup("127.0.0.1") is None

    def test_no_api_key_returns_none(self, tmp_db, monkeypatch):
        monkeypatch.setattr("server.threat_intel._ABUSEIPDB_KEY", "")
        monkeypatch.setattr("server.threat_intel._GREYNOISE_KEY", "")
        from server import threat_intel as ti
        monkeypatch.setattr(ti, "_feodo_data", {})
        monkeypatch.setattr(ti, "_feodo_last_fetch", float("inf"))

        tf_payload = {"query_status": "no_result", "data": []}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(tf_payload).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            from server.threat_intel import lookup
            result = lookup("8.8.8.8")
        assert result is not None
        assert result["composite_score"] == 0

    def test_api_response_cached(self, tmp_db, monkeypatch):
        monkeypatch.setattr("server.threat_intel._ABUSEIPDB_KEY", "test-key")
        monkeypatch.setattr("server.threat_intel._GREYNOISE_KEY", "")
        from server import threat_intel as ti
        monkeypatch.setattr(ti, "_feodo_data", {})
        monkeypatch.setattr(ti, "_feodo_last_fetch", float("inf"))

        abuse_data = {
            "data": {
                "abuseConfidenceScore": 75,
                "totalReports": 12,
                "countryCode": "CN",
                "isp": "TestISP",
            }
        }
        tf_data = {"query_status": "no_result", "data": []}

        def make_mock(payload):
            m = MagicMock()
            m.read.return_value = json.dumps(payload).encode()
            m.__enter__ = lambda s: s
            m.__exit__ = MagicMock(return_value=False)
            return m

        with patch("urllib.request.urlopen", side_effect=[make_mock(abuse_data), make_mock(tf_data)]):
            from server.threat_intel import lookup
            result = lookup("1.2.3.4")

        assert result is not None
        assert result["score"] == 75
        assert result["country_code"] == "CN"

    def test_cached_result_returned_without_api_call(self, tmp_db, monkeypatch):
        from server.database import db
        db.save_threat_intel("5.5.5.5", 30, 3, "US", "CachedISP")

        monkeypatch.setattr("server.threat_intel._ABUSEIPDB_KEY", "test-key")

        with patch("urllib.request.urlopen") as mock_url:
            from server.threat_intel import lookup
            result = lookup("5.5.5.5")
            mock_url.assert_not_called()

        assert result["score"] == 30
        assert result["isp"] == "CachedISP"


class TestFeodoCheck:
    def test_feodo_unlisted_ip(self, monkeypatch):
        from server import threat_intel as ti
        monkeypatch.setattr(ti, "_feodo_data", {})
        monkeypatch.setattr(ti, "_feodo_last_fetch", float("inf"))
        result = ti._feodo_check("1.2.3.4")
        assert result["listed"] is False

    def test_feodo_listed_ip(self, monkeypatch):
        from server import threat_intel as ti
        monkeypatch.setattr(ti, "_feodo_data", {
            "5.6.7.8": {"malware": "Emotet", "port": 443, "status": "online"}
        })
        monkeypatch.setattr(ti, "_feodo_last_fetch", float("inf"))
        result = ti._feodo_check("5.6.7.8")
        assert result["listed"] is True
        assert result["malware"] == "Emotet"

    def test_feodo_refresh_called_when_stale(self, monkeypatch):
        import time
        from server import threat_intel as ti
        stale_ts = time.monotonic() - ti._FEODO_TTL - 1
        monkeypatch.setattr(ti, "_feodo_last_fetch", stale_ts)
        calls = []

        def fake_refresh():
            calls.append(1)
            ti._feodo_data = {"9.9.9.9": {"malware": "QakBot", "port": 443, "status": "online"}}
            ti._feodo_last_fetch = time.monotonic()

        monkeypatch.setattr(ti, "_refresh_feodo", fake_refresh)
        ti._feodo_check("1.1.1.1")
        assert len(calls) == 1


class TestCompositeScore:
    def test_feodo_listed_dominates(self):
        from server.threat_intel import _compute_composite
        score = _compute_composite(0, True, 0, False, False, "")
        assert score >= 85

    def test_greynoise_riot_caps_score(self):
        from server.threat_intel import _compute_composite
        score = _compute_composite(100, False, 100, False, True, "benign")
        assert score <= 20

    def test_greynoise_noise_caps_score(self):
        from server.threat_intel import _compute_composite
        score = _compute_composite(80, False, 80, True, False, "unknown")
        assert score <= 40

    def test_all_sources_combined(self):
        from server.threat_intel import _compute_composite
        score = _compute_composite(70, True, 80, False, False, "malicious")
        assert score == 100

    def test_zero_threat(self):
        from server.threat_intel import _compute_composite
        score = _compute_composite(0, False, 0, False, False, "")
        assert score == 0


class TestThreatFoxQuery:
    def test_no_results(self, monkeypatch):
        from server.threat_intel import _query_threatfox
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"query_status": "no_result", "data": []}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _query_threatfox("1.2.3.4")
        assert result["score"] == 0

    def test_result_returned(self, monkeypatch):
        from server.threat_intel import _query_threatfox
        payload = {
            "query_status": "ok",
            "data": [{"ioc_type": "ip:port", "malware": "AsyncRAT", "confidence_level": 75}]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(payload).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = _query_threatfox("1.2.3.4")
        assert result["score"] == 75
        assert result["malware"] == "AsyncRAT"


class TestGreyNoiseQuery:
    def test_no_key_returns_empty(self, monkeypatch):
        from server import threat_intel as ti
        monkeypatch.setattr(ti, "_GREYNOISE_KEY", "")
        result = ti._query_greynoise("1.2.3.4")
        assert result["noise"] is False
        assert result["riot"] is False

    def test_result_parsed(self, monkeypatch):
        from server import threat_intel as ti
        monkeypatch.setattr(ti, "_GREYNOISE_KEY", "test-key")
        payload = {"ip": "1.2.3.4", "noise": True, "riot": False, "classification": "malicious"}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(payload).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = ti._query_greynoise("1.2.3.4")
        assert result["noise"] is True
        assert result["classification"] == "malicious"


class TestFullLookup:
    def test_composite_score_in_result(self, tmp_db, monkeypatch):
        from server import threat_intel as ti
        monkeypatch.setattr(ti, "_ABUSEIPDB_KEY", "")
        monkeypatch.setattr(ti, "_feodo_data", {})
        monkeypatch.setattr(ti, "_feodo_last_fetch", float("inf"))
        monkeypatch.setattr(ti, "_GREYNOISE_KEY", "")

        tf_payload = {"query_status": "no_result", "data": []}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(tf_payload).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = ti.lookup("8.8.8.8")

        assert result is not None
        assert "composite_score" in result
        assert result["composite_score"] == 0


class TestIsPrivateIp:
    def test_rfc1918_addresses(self):
        from server.threat_intel import _is_private_ip
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("172.31.255.255") is True
        assert _is_private_ip("192.168.1.1") is True

    def test_loopback(self):
        from server.threat_intel import _is_private_ip
        assert _is_private_ip("127.0.0.1") is True
        assert _is_private_ip("::1") is True

    def test_link_local(self):
        from server.threat_intel import _is_private_ip
        assert _is_private_ip("169.254.0.1") is True
        assert _is_private_ip("fe80::1") is True

    def test_cgnat_rfc6598(self):
        from server.threat_intel import _is_private_ip
        assert _is_private_ip("100.64.0.1") is True
        assert _is_private_ip("100.127.255.255") is True

    def test_ipv6_ula(self):
        from server.threat_intel import _is_private_ip
        assert _is_private_ip("fc00::1") is True
        assert _is_private_ip("fd12:3456:789a::1") is True

    def test_public_addresses(self):
        from server.threat_intel import _is_private_ip
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.1.1.1") is False
        assert _is_private_ip("45.33.32.156") is False

    def test_invalid_input(self):
        from server.threat_intel import _is_private_ip
        assert _is_private_ip("not-an-ip") is False
        assert _is_private_ip("") is False
        assert _is_private_ip("999.999.999.999") is False
