"""N4 — Suricata ET kural güncelleme testleri."""

import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from server.auth import create_access_token
from server.main import app

client = TestClient(app)


def _auth(role: str = "admin") -> dict:
    token = create_access_token(username="admin", role=role)
    return {"Authorization": f"Bearer {token}"}


# ─────────────────────────────────────────── Script dosyası testleri ────

class TestScriptFile:

    def test_script_exists(self):
        script = Path(__file__).parent.parent / "scripts" / "suricata-update-cron.sh"
        assert script.exists(), "suricata-update-cron.sh bulunamadı"

    def test_script_has_shebang(self):
        script = Path(__file__).parent.parent / "scripts" / "suricata-update-cron.sh"
        first_line = script.read_text().splitlines()[0]
        assert first_line.startswith("#!/bin/bash")

    def test_script_has_strict_mode(self):
        script = Path(__file__).parent.parent / "scripts" / "suricata-update-cron.sh"
        content = script.read_text()
        assert "set -euo pipefail" in content

    def test_script_has_flock(self):
        script = Path(__file__).parent.parent / "scripts" / "suricata-update-cron.sh"
        assert "flock" in script.read_text()

    def test_script_uses_no_reload_flag(self):
        script = Path(__file__).parent.parent / "scripts" / "suricata-update-cron.sh"
        assert "--no-reload" in script.read_text()

    def test_script_writes_state_file(self):
        script = Path(__file__).parent.parent / "scripts" / "suricata-update-cron.sh"
        assert "STATE_FILE" in script.read_text()

    def test_script_has_suricatasc_reload(self):
        script = Path(__file__).parent.parent / "scripts" / "suricata-update-cron.sh"
        assert "suricatasc" in script.read_text()

    def test_script_has_usr2_fallback(self):
        script = Path(__file__).parent.parent / "scripts" / "suricata-update-cron.sh"
        assert "USR2" in script.read_text()

    def test_script_has_log_file(self):
        script = Path(__file__).parent.parent / "scripts" / "suricata-update-cron.sh"
        assert "LOG_FILE" in script.read_text()

    def test_script_has_et_open_source(self):
        script = Path(__file__).parent.parent / "scripts" / "suricata-update-cron.sh"
        assert "et/open" in script.read_text()

    def test_script_has_env_overrides(self):
        script = Path(__file__).parent.parent / "scripts" / "suricata-update-cron.sh"
        content = script.read_text()
        for var in ("SURICATA_CONF", "DISABLE_CONF", "MODIFY_CONF", "STATE_FILE"):
            assert var in content, f"Env override eksik: {var}"


# ─────────────────────────────────────────── Config dosyaları testleri ────

class TestConfigFiles:

    def test_disable_conf_exists(self):
        f = Path(__file__).parent.parent / "config" / "suricata" / "disable.conf"
        assert f.exists()

    def test_modify_conf_exists(self):
        f = Path(__file__).parent.parent / "config" / "suricata" / "modify.conf"
        assert f.exists()

    def test_disable_conf_has_fp_groups(self):
        f = Path(__file__).parent.parent / "config" / "suricata" / "disable.conf"
        content = f.read_text()
        assert "emerging-games" in content
        assert "emerging-chat" in content
        assert "emerging-policy" in content

    def test_disable_conf_has_comments(self):
        f = Path(__file__).parent.parent / "config" / "suricata" / "disable.conf"
        lines = f.read_text().splitlines()
        comment_lines = [l for l in lines if l.startswith("#")]
        assert len(comment_lines) >= 5

    def test_modify_conf_has_comments(self):
        f = Path(__file__).parent.parent / "config" / "suricata" / "modify.conf"
        content = f.read_text()
        assert "#" in content

    def test_systemd_service_exists(self):
        f = Path(__file__).parent.parent / "scripts" / "netguard-suricata-update.service"
        assert f.exists()
        content = f.read_text()
        assert "ExecStart" in content
        assert "suricata-update-cron.sh" in content

    def test_systemd_timer_exists(self):
        f = Path(__file__).parent.parent / "scripts" / "netguard-suricata-update.timer"
        assert f.exists()
        content = f.read_text()
        assert "OnCalendar" in content
        assert "03:00:00" in content

    def test_cron_template_exists(self):
        f = Path(__file__).parent.parent / "scripts" / "netguard-suricata-update.cron"
        assert f.exists()
        content = f.read_text()
        assert "suricata-update-cron.sh" in content
        assert "0 3 * * *" in content


# ─────────────────────────────────────────── State JSON testleri ────

class TestStateJson:

    def _valid_state(self) -> dict:
        return {
            "job_id": "test-job-001",
            "last_updated": "2026-06-02T03:00:00Z",
            "rule_count": 35000,
            "status": "success",
            "reload_status": "ok",
            "duration_ms": 45000,
            "error": None,
            "checksum": "abc123",
            "sources": "et/open",
        }

    def test_valid_state_fields(self):
        state = self._valid_state()
        required = {"job_id", "last_updated", "rule_count", "status", "reload_status"}
        for field in required:
            assert field in state

    def test_status_values(self):
        valid_statuses = {"success", "failed", "partial", "running", "never_run"}
        for s in valid_statuses:
            state = self._valid_state()
            state["status"] = s
            assert state["status"] in valid_statuses

    def test_state_json_round_trip(self, tmp_path):
        state = self._valid_state()
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(state))
        loaded = json.loads(state_file.read_text())
        assert loaded["rule_count"] == 35000
        assert loaded["status"] == "success"


# ─────────────────────────────────────────── API endpoint testleri ────

class TestSuricataUpdateStatusEndpoint:

    def test_requires_auth(self, tmp_db):
        r = client.get("/api/v1/maintenance/suricata-update/status")
        assert r.status_code == 401

    def test_non_admin_rejected(self, tmp_db):
        token = create_access_token(username="viewer", role="viewer")
        r = client.get(
            "/api/v1/maintenance/suricata-update/status",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_never_run_when_no_state_file(self, tmp_db):
        with patch("server.routes.maintenance._SURICATA_STATE_FILE", Path("/nonexistent/path.json")):
            r = client.get("/api/v1/maintenance/suricata-update/status", headers=_auth())
        assert r.status_code == 200
        assert r.json()["status"] == "never_run"
        assert r.json()["last_updated"] is None

    def test_returns_state_from_file(self, tmp_db, tmp_path):
        state = {
            "job_id": "test-001",
            "last_updated": "2026-06-02T03:00:00Z",
            "rule_count": 35000,
            "status": "success",
            "reload_status": "ok",
            "duration_ms": 45000,
            "error": None,
            "checksum": "abc",
            "sources": "et/open",
        }
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(state))
        with patch("server.routes.maintenance._SURICATA_STATE_FILE", state_file):
            r = client.get("/api/v1/maintenance/suricata-update/status", headers=_auth())
        assert r.status_code == 200
        data = r.json()
        assert data["rule_count"] == 35000
        assert data["status"] == "success"

    def test_invalid_json_returns_500(self, tmp_db, tmp_path):
        state_file = tmp_path / "state.json"
        state_file.write_text("{invalid json}")
        with patch("server.routes.maintenance._SURICATA_STATE_FILE", state_file):
            r = client.get("/api/v1/maintenance/suricata-update/status", headers=_auth())
        assert r.status_code == 500


class TestSuricataUpdateTriggerEndpoint:

    def test_requires_auth(self, tmp_db):
        r = client.post("/api/v1/maintenance/suricata-update/trigger")
        assert r.status_code == 401

    def test_non_admin_rejected(self, tmp_db):
        token = create_access_token(username="viewer", role="viewer")
        r = client.post(
            "/api/v1/maintenance/suricata-update/trigger",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403

    def test_script_missing_returns_503(self, tmp_db):
        with patch("server.routes.maintenance._SURICATA_UPDATE_SCRIPT", Path("/nonexistent.sh")):
            r = client.post("/api/v1/maintenance/suricata-update/trigger", headers=_auth())
        assert r.status_code == 503

    def test_trigger_starts_job(self, tmp_db, tmp_path):
        fake_script = tmp_path / "update.sh"
        fake_script.write_text("#!/bin/bash\nexit 0\n")
        fake_script.chmod(fake_script.stat().st_mode | stat.S_IEXEC)
        with patch("server.routes.maintenance._SURICATA_UPDATE_SCRIPT", fake_script), \
             patch("subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock()
            r = client.post("/api/v1/maintenance/suricata-update/trigger", headers=_auth())
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "started"
        assert "job_id" in data
        assert data["job_id"].startswith("api-")
        mock_popen.assert_called_once()

    def test_running_state_returns_409(self, tmp_db, tmp_path):
        fake_script = tmp_path / "update.sh"
        fake_script.write_text("#!/bin/bash\n")
        fake_script.chmod(fake_script.stat().st_mode | stat.S_IEXEC)
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({"status": "running", "job_id": "old-job"}))
        with patch("server.routes.maintenance._SURICATA_UPDATE_SCRIPT", fake_script), \
             patch("server.routes.maintenance._SURICATA_STATE_FILE", state_file):
            r = client.post("/api/v1/maintenance/suricata-update/trigger", headers=_auth())
        assert r.status_code == 409

    def test_audit_log_written(self, tmp_db, tmp_path):
        from server.database import db as _db
        fake_script = tmp_path / "update.sh"
        fake_script.write_text("#!/bin/bash\n")
        fake_script.chmod(fake_script.stat().st_mode | stat.S_IEXEC)
        with patch("server.routes.maintenance._SURICATA_UPDATE_SCRIPT", fake_script), \
             patch("subprocess.Popen") as mock_popen:
            mock_popen.return_value = MagicMock()
            r = client.post("/api/v1/maintenance/suricata-update/trigger", headers=_auth())
        assert r.status_code == 200
        logs = _db.get_audit_log(limit=5, actor="admin")
        actions = [e["action"] for e in logs]
        assert "suricata_update.trigger" in actions
