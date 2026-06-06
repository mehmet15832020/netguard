"""
C4 — Sensor Sağlık Metrikleri testleri.

Zeek stats.log parse, Suricata EVE stats, arayüz istatistikleri,
/api/v1/health/sensors endpoint.

CIS Control 13.1 — ağ izleme kapasitesinin doğrulanması.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from server.main import app

client = TestClient(app)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _zeek_json_line(pkts_proc=1000, drop_rate=0.0, bytes_recv=512000, ts=None) -> str:
    ts = ts or datetime.now(timezone.utc).timestamp()
    return json.dumps({
        "ts": ts,
        "pkts_proc": pkts_proc,
        "pkt_drop_rate": drop_rate,
        "bytes_recv": bytes_recv,
    })


def _suricata_stats_line(kernel_packets=10000, kernel_drops=0, decoder_pkts=9900) -> str:
    return json.dumps({
        "event_type": "stats",
        "timestamp": "2026-06-06T10:00:00.000000+0000",
        "stats": {
            "capture": {
                "kernel_packets": kernel_packets,
                "kernel_drops": kernel_drops,
            },
            "decoder": {"pkts": decoder_pkts},
        },
    })


# ─── get_zeek_stats ───────────────────────────────────────────────────────────

class TestGetZeekStats:

    def test_unknown_when_file_missing(self):
        from server.sensor_health import get_zeek_stats
        result = get_zeek_stats(Path("/nonexistent/stats.log"))
        assert result["status"] == "unknown"
        assert result["error"] is not None

    def test_parses_json_format(self, tmp_path):
        from server.sensor_health import get_zeek_stats
        f = tmp_path / "stats.log"
        f.write_text(_zeek_json_line(pkts_proc=5000, drop_rate=0.0, bytes_recv=1024) + "\n")
        result = get_zeek_stats(f)
        assert result["status"] == "ok"
        assert result["pkts_proc"] == 5000
        assert result["drop_rate"] == 0.0
        assert result["bytes_recv"] == 1024

    def test_status_ok_zero_drops(self, tmp_path):
        from server.sensor_health import get_zeek_stats
        f = tmp_path / "stats.log"
        f.write_text(_zeek_json_line(drop_rate=0.0) + "\n")
        assert get_zeek_stats(f)["status"] == "ok"

    def test_status_warning_five_pct(self, tmp_path):
        from server.sensor_health import get_zeek_stats
        f = tmp_path / "stats.log"
        f.write_text(_zeek_json_line(drop_rate=0.07) + "\n")
        assert get_zeek_stats(f)["status"] == "warning"

    def test_status_critical_fifteen_pct(self, tmp_path):
        from server.sensor_health import get_zeek_stats
        f = tmp_path / "stats.log"
        f.write_text(_zeek_json_line(drop_rate=0.20) + "\n")
        assert get_zeek_stats(f)["status"] == "critical"

    def test_parses_tsv_format(self, tmp_path):
        from server.sensor_health import get_zeek_stats
        f = tmp_path / "stats.log"
        ts = str(datetime.now(timezone.utc).timestamp())
        f.write_text(
            "#separator \\x09\n"
            "#fields\tts\tpeer\tmem\tpkts_proc\tbytes_recv\tpkts_dropped\tpkts_link\tpkt_drop_rate\n"
            f"{ts}\tzeek\t50\t2000\t102400\t0\t2000\t0.03\n"
        )
        result = get_zeek_stats(f)
        assert result["pkts_proc"] == 2000
        assert result["drop_rate"] == 0.03

    def test_skips_comment_lines(self, tmp_path):
        from server.sensor_health import get_zeek_stats
        f = tmp_path / "stats.log"
        f.write_text(
            "# comment\n"
            "#fields ts pkts_proc\n"
            + _zeek_json_line(pkts_proc=999) + "\n"
        )
        result = get_zeek_stats(f)
        assert result["pkts_proc"] == 999

    def test_empty_file_returns_error(self, tmp_path):
        from server.sensor_health import get_zeek_stats
        f = tmp_path / "stats.log"
        f.write_text("")
        result = get_zeek_stats(f)
        assert result["status"] == "unknown"
        assert result["error"] is not None

    def test_absent_pkt_drop_rate_json_returns_unknown(self, tmp_path):
        from server.sensor_health import get_zeek_stats
        f = tmp_path / "stats.log"
        f.write_text(json.dumps({"ts": 1.0, "pkts_proc": 500, "bytes_recv": 1024}) + "\n")
        result = get_zeek_stats(f)
        assert result["status"] == "unknown"
        assert result["error"] is not None

    def test_tsv_without_fields_header_returns_error(self, tmp_path):
        from server.sensor_health import get_zeek_stats
        f = tmp_path / "stats.log"
        f.write_text("not-json-no-header\t500\t1024\t0.01\n")
        result = get_zeek_stats(f)
        assert result["status"] == "unknown"
        assert result["error"] is not None


# ─── get_suricata_stats ───────────────────────────────────────────────────────

class TestGetSuricataStats:

    def test_unknown_when_file_missing(self):
        from server.sensor_health import get_suricata_stats
        result = get_suricata_stats(Path("/nonexistent/eve.json"))
        assert result["status"] == "unknown"
        assert result["error"] is not None

    def test_finds_last_stats_event(self, tmp_path):
        from server.sensor_health import get_suricata_stats
        f = tmp_path / "eve.json"
        lines = [
            json.dumps({"event_type": "alert", "timestamp": "2026-06-06T09:00:00"}),
            _suricata_stats_line(kernel_packets=10000, kernel_drops=0),
        ]
        f.write_text("\n".join(lines) + "\n")
        result = get_suricata_stats(f)
        assert result["status"] == "ok"
        assert result["kernel_packets"] == 10000

    def test_computes_drop_rate(self, tmp_path):
        from server.sensor_health import get_suricata_stats
        f = tmp_path / "eve.json"
        f.write_text(_suricata_stats_line(kernel_packets=900, kernel_drops=100) + "\n")
        result = get_suricata_stats(f)
        assert result["drop_rate"] == pytest.approx(0.1, abs=0.001)
        assert result["status"] == "warning"

    def test_critical_status_high_drops(self, tmp_path):
        from server.sensor_health import get_suricata_stats
        f = tmp_path / "eve.json"
        f.write_text(_suricata_stats_line(kernel_packets=800, kernel_drops=200) + "\n")
        result = get_suricata_stats(f)
        assert result["status"] == "critical"

    def test_no_stats_event_returns_error(self, tmp_path):
        from server.sensor_health import get_suricata_stats
        f = tmp_path / "eve.json"
        f.write_text(json.dumps({"event_type": "alert"}) + "\n")
        result = get_suricata_stats(f)
        assert result["status"] == "unknown"
        assert "stats" in result["error"]

    def test_decoder_packets_included(self, tmp_path):
        from server.sensor_health import get_suricata_stats
        f = tmp_path / "eve.json"
        f.write_text(_suricata_stats_line(decoder_pkts=7777) + "\n")
        result = get_suricata_stats(f)
        assert result["decoder_packets"] == 7777


# ─── get_interface_stats ──────────────────────────────────────────────────────

class TestGetInterfaceStats:

    def test_returns_list(self):
        from server.sensor_health import get_interface_stats
        result = get_interface_stats()
        assert isinstance(result, list)

    def test_filters_loopback(self):
        from server.sensor_health import get_interface_stats
        result = get_interface_stats()
        names = [r["interface"] for r in result]
        assert "lo" not in names

    def test_drop_rate_computed(self):
        from server.sensor_health import get_interface_stats

        fake_stats = {
            "eth0": MagicMock(
                packets_recv=900, dropin=100, dropout=0,
                bytes_recv=1000000, bytes_sent=500000,
            ),
        }
        with patch("server.sensor_health.psutil.net_io_counters", return_value=fake_stats):
            result = get_interface_stats()

        assert len(result) == 1
        assert result[0]["interface"] == "eth0"
        assert result[0]["drop_rate"] == pytest.approx(0.1, abs=0.001)
        assert result[0]["status"] == "warning"

    def test_filters_docker_interfaces(self):
        from server.sensor_health import get_interface_stats

        fake_stats = {
            "docker0": MagicMock(packets_recv=100, dropin=0, dropout=0, bytes_recv=0, bytes_sent=0),
            "eth0":    MagicMock(packets_recv=200, dropin=0, dropout=0, bytes_recv=0, bytes_sent=0),
        }
        with patch("server.sensor_health.psutil.net_io_counters", return_value=fake_stats):
            result = get_interface_stats()

        names = [r["interface"] for r in result]
        assert "docker0" not in names
        assert "eth0" in names

    def test_bad_interface_does_not_abort_loop(self):
        from server.sensor_health import get_interface_stats

        bad = MagicMock()
        bad.packets_recv = MagicMock(side_effect=AttributeError("broken"))
        good = MagicMock(packets_recv=500, dropin=0, dropout=0, bytes_recv=0, bytes_sent=0)

        fake_stats = {"eth0": bad, "eth1": good}
        with patch("server.sensor_health.psutil.net_io_counters", return_value=fake_stats):
            result = get_interface_stats()

        names = [r["interface"] for r in result]
        assert "eth1" in names


# ─── get_all_sensor_health ────────────────────────────────────────────────────

class TestGetAllSensorHealth:

    def _mocked_health(self, zeek_status="ok", suricata_status="ok"):
        from server.sensor_health import get_all_sensor_health

        with (
            patch("server.sensor_health.get_zeek_stats",     return_value={"name": "zeek", "status": zeek_status}),
            patch("server.sensor_health.get_suricata_stats", return_value={"name": "suricata", "status": suricata_status}),
            patch("server.sensor_health.get_interface_stats", return_value=[]),
        ):
            return get_all_sensor_health()

    def test_overall_ok_when_both_ok(self):
        result = self._mocked_health("ok", "ok")
        assert result["overall"] == "ok"

    def test_overall_warning_if_one_warning(self):
        result = self._mocked_health("ok", "warning")
        assert result["overall"] == "warning"

    def test_overall_critical_if_one_critical(self):
        result = self._mocked_health("ok", "critical")
        assert result["overall"] == "critical"

    def test_overall_critical_takes_precedence(self):
        result = self._mocked_health("warning", "critical")
        assert result["overall"] == "critical"

    def test_overall_unknown_when_both_unknown(self):
        result = self._mocked_health("unknown", "unknown")
        assert result["overall"] == "unknown"

    def test_response_contains_zeek_and_suricata(self):
        result = self._mocked_health()
        assert "zeek" in result["sensors"]
        assert "suricata" in result["sensors"]

    def test_thresholds_in_response(self):
        result = self._mocked_health()
        assert "warn" in result["thresholds"]
        assert "critical" in result["thresholds"]

    def test_timestamp_present(self):
        result = self._mocked_health()
        assert "timestamp" in result
        datetime.fromisoformat(result["timestamp"])


# ─── /api/v1/health/sensors route ────────────────────────────────────────────

class TestSensorsRoute:

    def test_requires_auth(self):
        r = client.get("/api/v1/health/sensors")
        assert r.status_code in (401, 403)

    def test_returns_200_with_auth(self, admin_token):
        with patch("server.sensor_health.get_zeek_stats",     return_value={"name": "zeek",     "status": "ok"}):
            with patch("server.sensor_health.get_suricata_stats", return_value={"name": "suricata", "status": "ok"}):
                with patch("server.sensor_health.get_interface_stats", return_value=[]):
                    r = client.get(
                        "/api/v1/health/sensors",
                        headers={"Authorization": f"Bearer {admin_token}"},
                    )
        assert r.status_code == 200

    def test_response_schema(self, admin_token):
        with patch("server.sensor_health.get_all_sensor_health", return_value={
            "overall": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sensors": {"zeek": {"status": "ok"}, "suricata": {"status": "ok"}},
            "interfaces": [],
            "thresholds": {"warn": 0.05, "critical": 0.15},
        }):
            r = client.get(
                "/api/v1/health/sensors",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        data = r.json()
        assert "overall" in data
        assert "sensors" in data
        assert "interfaces" in data
        assert "thresholds" in data
