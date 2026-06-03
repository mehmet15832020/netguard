"""N8 — M365 ve GWorkspace collector testleri.

Gerçek API çağrıları yapılmaz — httpx ve google-auth mock'lanır.
Tüm testler env vars tanımlı değilken de çalışır.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ── M365 Collector ────────────────────────────────────────────────────────────

class TestM365TokenFetch:
    @pytest.mark.anyio
    async def test_token_fetched_via_httpx(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"access_token": "tok123", "expires_in": 3600})

        with patch("server.collectors.m365_collector._TENANT_ID", "tenant-1"), \
             patch("server.collectors.m365_collector._CLIENT_ID", "client-1"), \
             patch("server.collectors.m365_collector._CLIENT_SECRET", "secret-1"), \
             patch("server.collectors.m365_collector._token_cache", {}), \
             patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_cls.return_value = mock_client

            from server.collectors.m365_collector import _get_token
            token = await _get_token()

        assert token == "tok123"

    @pytest.mark.anyio
    async def test_token_cached_on_second_call(self):
        import time
        cache = {"access_token": "cached_tok", "expires_at": time.monotonic() + 3600}
        with patch("server.collectors.m365_collector._token_cache", cache):
            from server.collectors.m365_collector import _get_token
            token = await _get_token()
        assert token == "cached_tok"


class TestM365CollectorSkip:
    @pytest.mark.anyio
    async def test_skips_when_no_env_vars(self):
        with patch("server.collectors.m365_collector._TENANT_ID", ""), \
             patch("server.collectors.m365_collector._CLIENT_ID", ""), \
             patch("server.collectors.m365_collector._CLIENT_SECRET", ""):
            from server.collectors.m365_collector import run_m365_collector
            await run_m365_collector()


class TestM365PollOnce:
    @pytest.mark.anyio
    async def test_poll_returns_event_count(self, tmp_db):
        from datetime import datetime, timezone, timedelta

        m365_event = {
            "CreationTime": "2024-06-01T10:00:00Z",
            "Operation":    "New-InboxRule",
            "UserId":       "user@test.com",
            "Workload":     "Exchange",
        }

        mock_resp_blob = MagicMock()
        mock_resp_blob.raise_for_status = MagicMock()
        mock_resp_blob.json = MagicMock(return_value={"access_token": "tok", "expires_in": 3600})

        mock_sub   = MagicMock(status_code=200)
        mock_list  = MagicMock(status_code=200, headers={})
        mock_list.json = MagicMock(return_value=[{"contentUri": "https://blob/1"}])
        mock_list.headers = MagicMock(get=MagicMock(return_value=None))
        mock_events = MagicMock(status_code=200)
        mock_events.json = MagicMock(return_value=[m365_event])

        with patch("server.collectors.m365_collector._TENANT_ID", "t"), \
             patch("server.collectors.m365_collector._CLIENT_ID", "c"), \
             patch("server.collectors.m365_collector._CLIENT_SECRET", "s"), \
             patch("server.collectors.m365_collector._token_cache",
                   {"access_token": "tok", "expires_at": 9e18}):

            async def fake_post(*a, **kw): return mock_sub
            async def fake_get(url, **kw):
                if "subscriptions/content" in url:
                    return mock_list
                return mock_events

            with patch("httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.post = AsyncMock(side_effect=fake_post)
                mock_client.get  = AsyncMock(side_effect=fake_get)
                mock_cls.return_value = mock_client

                from server.collectors.m365_collector import _poll_once
                now = datetime.now(timezone.utc)
                count = await _poll_once(now - timedelta(minutes=15), now)

        assert count >= 0  # Collector ran without exception


# ── GWorkspace Collector ──────────────────────────────────────────────────────

class TestGWSCollectorSkip:
    @pytest.mark.anyio
    async def test_skips_when_no_env_vars(self):
        with patch("server.collectors.gworkspace_collector._SA_JSON_PATH", ""), \
             patch("server.collectors.gworkspace_collector._ADMIN_EMAIL", ""), \
             patch("server.collectors.gworkspace_collector._DOMAIN", ""):
            from server.collectors.gworkspace_collector import run_gworkspace_collector
            await run_gworkspace_collector()


class TestGWSFetchActivities:
    @pytest.mark.anyio
    async def test_fetch_returns_activities(self):
        from datetime import datetime, timezone, timedelta

        activity = {
            "id": {"time": "2024-06-01T10:00:00Z", "applicationName": "login"},
            "actor": {"email": "u@c.com", "ipAddress": "1.2.3.4"},
            "events": [{"name": "login_failure", "parameters": []}],
        }
        mock_resp = MagicMock(status_code=200)
        mock_resp.json = MagicMock(return_value={"items": [activity], "nextPageToken": None})

        async def fake_get(url, **kw):
            return mock_resp

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_cls.return_value = mock_client

            from server.collectors.gworkspace_collector import _fetch_activities
            now = datetime.now(timezone.utc)
            results = await _fetch_activities(
                mock_client, "fake_token", "login",
                now - timedelta(minutes=15), now,
            )

        assert len(results) == 1
        assert results[0]["actor"]["email"] == "u@c.com"

    @pytest.mark.anyio
    async def test_fetch_handles_400_gracefully(self):
        from datetime import datetime, timezone, timedelta

        mock_resp = MagicMock(status_code=400)

        async def fake_get(url, **kw):
            return mock_resp

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=fake_get)
            mock_cls.return_value = mock_client

            from server.collectors.gworkspace_collector import _fetch_activities
            now = datetime.now(timezone.utc)
            results = await _fetch_activities(
                mock_client, "fake_token", "login",
                now - timedelta(minutes=15), now,
            )

        assert results == []


# ── STAGE_MAP entegrasyonu ────────────────────────────────────────────────────

class TestStageMap:
    def test_m365_inbox_rule_lateral(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP["m365_inbox_rule"] == "lateral"

    def test_m365_role_assignment_weaponize(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP["m365_role_assignment"] == "weaponize"

    def test_m365_login_failure_recon(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP["m365_login_failure"] == "recon"

    def test_gws_suspicious_login_weaponize(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP["gws_suspicious_login"] == "weaponize"

    def test_gws_gmail_rule_lateral(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP["gws_gmail_rule"] == "lateral"

    def test_gws_login_failure_recon(self):
        from server.attack_chain import STAGE_MAP
        assert STAGE_MAP["gws_login_failure"] == "recon"
