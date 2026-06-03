"""N7 — CISA KEV Monitor testleri.

DB metotları: upsert_kev_entries, get_kev_entries, get_kev_stats
Yardımcılar: _parse_entries, _is_monitored, _build_notification_body
fetch_kev_once: httpx mock ile
API: GET /maintenance/kev/status, POST /maintenance/kev/fetch
"""

import json
import uuid
from datetime import date
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from server.collectors.kev_monitor import (
    _parse_entries,
    _is_monitored,
    _build_notification_body,
    fetch_kev_once,
)
from server.main import app

client = TestClient(app)


def _auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


_SAMPLE_KEV_JSON = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2024.06.01",
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "Cisco",
            "product": "IOS XE",
            "vulnerabilityName": "Cisco IOS XE RCE",
            "dateAdded": "2024-06-01",
            "dueDate": "2024-06-22",
            "shortDescription": "Remote code execution in Cisco IOS XE.",
            "requiredAction": "Apply mitigations per vendor instructions.",
        },
        {
            "cveID": "CVE-2024-0002",
            "vendorProject": "Microsoft",
            "product": "Windows Server",
            "vulnerabilityName": "Windows Server Priv Esc",
            "dateAdded": "2024-06-01",
            "dueDate": "2024-06-22",
            "shortDescription": "Privilege escalation in Windows Server.",
            "requiredAction": "Apply updates.",
        },
    ],
}


# ── 1. _parse_entries ─────────────────────────────────────────────────────

class TestParseEntries:
    def test_parses_two_entries(self):
        entries = _parse_entries(_SAMPLE_KEV_JSON)
        assert len(entries) == 2

    def test_cve_id_extracted(self):
        entries = _parse_entries(_SAMPLE_KEV_JSON)
        cve_ids = {e["cve_id"] for e in entries}
        assert "CVE-2024-0001" in cve_ids

    def test_vendor_extracted(self):
        entries = _parse_entries(_SAMPLE_KEV_JSON)
        cisco = next(e for e in entries if e["cve_id"] == "CVE-2024-0001")
        assert cisco["vendor_project"] == "Cisco"

    def test_empty_vulnerabilities(self):
        assert _parse_entries({"vulnerabilities": []}) == []

    def test_missing_vulnerabilities_key(self):
        assert _parse_entries({}) == []

    def test_entry_without_cve_id_skipped(self):
        raw = {"vulnerabilities": [{"vendorProject": "X", "product": "Y"}]}
        assert _parse_entries(raw) == []


# ── 2. _is_monitored ─────────────────────────────────────────────────────

class TestIsMonitored:
    def test_cisco_monitored(self):
        assert _is_monitored("Cisco") is True

    def test_microsoft_monitored(self):
        assert _is_monitored("Microsoft") is True

    def test_unknown_vendor_not_monitored(self):
        assert _is_monitored("AcmeCorp") is False

    def test_case_insensitive(self):
        assert _is_monitored("CISCO SYSTEMS") is True


# ── 3. DB metotları ───────────────────────────────────────────────────────

class TestKevDatabase:
    def test_upsert_new_entries(self, tmp_db):
        entries = _parse_entries(_SAMPLE_KEV_JSON)
        new_ids = tmp_db.upsert_kev_entries(entries)
        assert len(new_ids) == 2
        assert "CVE-2024-0001" in new_ids

    def test_duplicate_not_inserted_twice(self, tmp_db):
        entries = _parse_entries(_SAMPLE_KEV_JSON)
        tmp_db.upsert_kev_entries(entries)
        new_ids = tmp_db.upsert_kev_entries(entries)
        assert new_ids == []

    def test_get_kev_entries(self, tmp_db):
        tmp_db.upsert_kev_entries(_parse_entries(_SAMPLE_KEV_JSON))
        rows = tmp_db.get_kev_entries(limit=10)
        assert len(rows) == 2

    def test_get_kev_entries_vendor_filter(self, tmp_db):
        tmp_db.upsert_kev_entries(_parse_entries(_SAMPLE_KEV_JSON))
        rows = tmp_db.get_kev_entries(vendor="cisco")
        assert len(rows) == 1
        assert rows[0]["cve_id"] == "CVE-2024-0001"

    def test_get_kev_stats_total(self, tmp_db):
        tmp_db.upsert_kev_entries(_parse_entries(_SAMPLE_KEV_JSON))
        stats = tmp_db.get_kev_stats()
        assert stats["total_cves"] == 2

    def test_get_kev_stats_empty(self, tmp_db):
        stats = tmp_db.get_kev_stats()
        assert stats["total_cves"] == 0
        assert stats["last_cve_date"] is None

    def test_upsert_empty_list(self, tmp_db):
        assert tmp_db.upsert_kev_entries([]) == []


# ── 4. fetch_kev_once ────────────────────────────────────────────────────

class TestFetchKevOnce:
    @pytest.mark.asyncio
    async def test_fetch_stores_new_entries(self, tmp_db):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value=_SAMPLE_KEV_JSON)

        with patch("server.collectors.kev_monitor.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await fetch_kev_once()

        assert result["status"] == "ok"
        assert result["new_count"] == 2

    @pytest.mark.asyncio
    async def test_fetch_http_error_returns_error(self, tmp_db):
        import httpx as _httpx

        with patch("server.collectors.kev_monitor.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(
                side_effect=_httpx.HTTPStatusError("404", request=MagicMock(), response=MagicMock())
            )
            mock_client_cls.return_value = mock_client

            result = await fetch_kev_once()

        assert result["status"] == "error"
        assert result["new_count"] == 0


# ── 5. API endpoint'leri ──────────────────────────────────────────────────

class TestKevApiEndpoints:
    def test_kev_status_200(self, admin_token, tmp_db):
        r = client.get("/api/v1/maintenance/kev/status", headers=_auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert "stats" in data
        assert "monitored_vendors" in data
        assert "entries" in data

    def test_kev_status_requires_admin(self, tmp_db):
        r = client.get("/api/v1/maintenance/kev/status")
        assert r.status_code == 401

    def test_kev_status_shows_entries(self, admin_token, tmp_db):
        tmp_db.upsert_kev_entries(_parse_entries(_SAMPLE_KEV_JSON))
        r = client.get("/api/v1/maintenance/kev/status", headers=_auth(admin_token))
        assert r.json()["stats"]["total_cves"] == 2

    def test_kev_fetch_trigger(self, admin_token, tmp_db):
        mock_result = {"status": "ok", "total": 2, "new_count": 2}
        with patch("server.routes.maintenance.fetch_kev_once", AsyncMock(return_value=mock_result)):
            r = client.post("/api/v1/maintenance/kev/fetch", headers=_auth(admin_token))
        assert r.status_code == 200
        assert r.json()["new_count"] == 2

    def test_kev_fetch_requires_admin(self, tmp_db):
        r = client.post("/api/v1/maintenance/kev/fetch")
        assert r.status_code == 401

    def test_kev_fetch_error_returns_502(self, admin_token, tmp_db):
        mock_result = {"status": "error", "detail": "timeout", "new_count": 0}
        with patch("server.routes.maintenance.fetch_kev_once", AsyncMock(return_value=mock_result)):
            r = client.post("/api/v1/maintenance/kev/fetch", headers=_auth(admin_token))
        assert r.status_code == 502
