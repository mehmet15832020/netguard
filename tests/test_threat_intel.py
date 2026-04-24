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
        monkeypatch.setattr("server.threat_intel._API_KEY", "")
        from server.threat_intel import lookup
        assert lookup("8.8.8.8") is None

    def test_api_response_cached(self, tmp_db, monkeypatch):
        monkeypatch.setattr("server.threat_intel._API_KEY", "test-key")

        api_data = {
            "data": {
                "abuseConfidenceScore": 75,
                "totalReports": 12,
                "countryCode": "CN",
                "isp": "TestISP",
            }
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(api_data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            from server.threat_intel import lookup
            result = lookup("1.2.3.4")

        assert result is not None
        assert result["score"] == 75
        assert result["country_code"] == "CN"

    def test_cached_result_returned_without_api_call(self, tmp_db, monkeypatch):
        from server.database import db
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        db.save_threat_intel("5.5.5.5", 30, 3, "US", "CachedISP")

        monkeypatch.setattr("server.threat_intel._API_KEY", "test-key")

        with patch("urllib.request.urlopen") as mock_url:
            from server.threat_intel import lookup
            result = lookup("5.5.5.5")
            mock_url.assert_not_called()

        assert result["score"] == 30
        assert result["isp"] == "CachedISP"
