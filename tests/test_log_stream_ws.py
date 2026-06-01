"""
F2 — Log Stream WebSocket broadcast testleri.

log_store.save() ve save_batch() DB'ye yazdıktan sonra
ws_manager.broadcast_from_thread("log", ...) çağırmalı.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from shared.models import NormalizedLog
from server.log_store import PostgreSQLLogStore


def _make_log(**kwargs) -> NormalizedLog:
    defaults = dict(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type="syslog",
        observer_hostname="test-host",
        timestamp=datetime.now(timezone.utc),
        severity="info",
        event_category="network",
        event_action="connection",
        message="test log",
    )
    return NormalizedLog(**{**defaults, **kwargs})


class TestLogStoreBroadcast:
    def test_save_calls_broadcast(self, tmp_db):
        store = PostgreSQLLogStore()
        log = _make_log()
        with patch("server.ws_manager.ws_manager.broadcast_from_thread") as mock_bc:
            store.save(log, tenant_id="default")
        mock_bc.assert_called_once()
        call_type, call_data = mock_bc.call_args[0]
        assert call_type == "log"
        assert call_data["log_id"] == log.log_id
        assert call_data["tenant_id"] == "default"

    def test_save_broadcast_includes_tenant(self, tmp_db):
        store = PostgreSQLLogStore()
        log = _make_log()
        with patch("server.ws_manager.ws_manager.broadcast_from_thread") as mock_bc:
            store.save(log, tenant_id="acme")
        _, data = mock_bc.call_args[0]
        assert data["tenant_id"] == "acme"

    def test_save_batch_broadcasts_each_log(self, tmp_db):
        store = PostgreSQLLogStore()
        logs = [_make_log() for _ in range(3)]
        with patch("server.ws_manager.ws_manager.broadcast_from_thread") as mock_bc:
            store.save_batch(logs, tenant_id="default")
        assert mock_bc.call_count == 3

    def test_save_batch_each_call_is_log_type(self, tmp_db):
        store = PostgreSQLLogStore()
        logs = [_make_log() for _ in range(2)]
        with patch("server.ws_manager.ws_manager.broadcast_from_thread") as mock_bc:
            store.save_batch(logs, tenant_id="default")
        for call in mock_bc.call_args_list:
            assert call[0][0] == "log"

    def test_save_db_write_succeeds_even_if_broadcast_raises(self, tmp_db):
        store = PostgreSQLLogStore()
        log = _make_log()
        with patch("server.ws_manager.ws_manager.broadcast_from_thread", side_effect=RuntimeError("ws down")):
            store.save(log, tenant_id="default")
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT log_id FROM normalized_logs WHERE log_id = %s", [log.log_id]
            ).fetchone()
        assert row is not None

    def test_broadcast_payload_has_key_fields(self, tmp_db):
        store = PostgreSQLLogStore()
        log = _make_log(source_ip="10.0.0.1", severity="high", event_action="ssh_failure")
        with patch("server.ws_manager.ws_manager.broadcast_from_thread") as mock_bc:
            store.save(log, tenant_id="default")
        _, data = mock_bc.call_args[0]
        assert data["source_ip"] == "10.0.0.1"
        assert data["severity"] == "high"
        assert data["event_action"] == "ssh_failure"
