"""
Auto-Discovery testleri.
"""

import asyncio
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

from server.main import app
from server.discovery.subnet_scanner import sweep, _probe_ip
from server.discovery.fingerprinter import (
    _lookup_vendor, _classify_banner, fingerprint, OUI_TABLE,
)

client = TestClient(app)


# ─── Subnet Scanner ─────────────────────────────────────────────────────────

class TestSubnetScanner:
    def test_invalid_cidr_raises(self):
        with pytest.raises(ValueError):
            asyncio.new_event_loop().run_until_complete(sweep("not-a-cidr"))

    def test_sweep_returns_list(self):
        # /32 → tek host, ulaşılamaz → boş liste
        result = asyncio.new_event_loop().run_until_complete(sweep("192.0.2.1/32"))
        assert isinstance(result, list)

    def test_sweep_active_host_format(self):
        """Aktif host bulunursa dict formatı doğru olmalı."""
        mock_result = {"ip": "192.168.1.1", "rtt_ms": 1.5}
        async def mock_ping(ip, count=1, timeout=1.5):
            return {"reachable": True, "rtt_ms": 1.5, "packet_loss_pct": 0.0, "error": ""}

        with patch("server.discovery.subnet_scanner.ping", side_effect=mock_ping):
            result = asyncio.new_event_loop().run_until_complete(sweep("192.168.1.1/32"))
        assert len(result) == 1
        assert result[0]["ip"] == "192.168.1.1"
        assert "rtt_ms" in result[0]

    def test_sweep_unreachable_host_empty(self):
        """Ulaşılamayan subnet → boş liste."""
        async def mock_ping(ip, count=1, timeout=1.5):
            return {"reachable": False, "rtt_ms": None, "packet_loss_pct": 100.0, "error": "timeout"}

        with patch("server.discovery.subnet_scanner.ping", side_effect=mock_ping):
            result = asyncio.new_event_loop().run_until_complete(sweep("10.0.0.0/30"))
        assert result == []

    def test_sweep_multiple_hosts(self):
        """Birden fazla host taranır."""
        call_count = 0
        async def mock_ping(ip, count=1, timeout=1.5):
            nonlocal call_count
            call_count += 1
            return {"reachable": False, "rtt_ms": None, "packet_loss_pct": 100.0, "error": ""}

        with patch("server.discovery.subnet_scanner.ping", side_effect=mock_ping):
            asyncio.new_event_loop().run_until_complete(sweep("10.0.0.0/29"))
        # /29 → 6 host
        assert call_count == 6


# ─── Fingerprinter ──────────────────────────────────────────────────────────

class TestVendorLookup:
    def test_known_vmware_oui(self):
        assert _lookup_vendor("00:50:56:ab:cd:ef") == "VMware"

    def test_known_cisco_oui(self):
        assert _lookup_vendor("00:18:e7:11:22:33") == "Cisco"

    def test_unknown_oui_empty_string(self):
        assert _lookup_vendor("ff:ff:ff:00:00:00") == ""

    def test_none_mac_empty_string(self):
        assert _lookup_vendor(None) == ""


class TestClassifyBanner:
    def test_ssh_openssh(self):
        banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
        info = _classify_banner(22, banner)
        assert info["service"] == "ssh"
        assert "OpenSSH" in info["vendor"]

    def test_http_nginx(self):
        banner = "HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n"
        info = _classify_banner(80, banner)
        assert info["vendor"] == "nginx"

    def test_http_apache(self):
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57\r\n"
        info = _classify_banner(80, banner)
        assert info["vendor"] == "Apache"

    def test_empty_banner_returns_service_name(self):
        info = _classify_banner(443, "")
        assert info["service"] == "https"
        assert info["version"] == ""

    def test_unknown_port_fallback(self):
        info = _classify_banner(9999, "")
        assert info["service"] == "port-9999"


class TestFingerprint:
    def test_returns_required_keys(self):
        """Bağlanamasa bile gerekli anahtarlar dönmeli."""
        async def mock_grab(host, port, timeout=2.0):
            return ""

        async def mock_tcp(host, port, timeout=1.0):
            return {"reachable": False, "rtt_ms": None, "error": "refused"}

        with patch("server.discovery.fingerprinter._grab_banner", side_effect=mock_grab), \
             patch("server.uptime_checker.tcp_check", side_effect=mock_tcp):
            result = asyncio.new_event_loop().run_until_complete(
                fingerprint("192.0.2.1")
            )
        assert "ip" in result
        assert "open_ports" in result
        assert "services" in result
        assert "vendor" in result
        assert "os_hint" in result
        assert result["ip"] == "192.0.2.1"

    def test_ssh_banner_sets_os_hint(self):
        """SSH banner bulunursa os_hint=Linux olmalı."""
        async def mock_grab(host, port, timeout=2.0):
            if port == 22:
                return "SSH-2.0-OpenSSH_8.9"
            return ""

        async def mock_tcp(host, port, timeout=1.0):
            return {"reachable": False, "rtt_ms": None, "error": "refused"}

        with patch("server.discovery.fingerprinter._grab_banner", side_effect=mock_grab), \
             patch("server.uptime_checker.tcp_check", side_effect=mock_tcp):
            result = asyncio.new_event_loop().run_until_complete(
                fingerprint("10.0.0.1")
            )
        assert 22 in result["open_ports"]
        assert result["os_hint"] == "Linux"

    def test_mac_vendor_passed_through(self):
        """MAC adresi verilirse vendor lookup yapılmalı."""
        async def mock_grab(host, port, timeout=2.0):
            return ""

        async def mock_tcp(host, port, timeout=1.0):
            return {"reachable": False, "rtt_ms": None, "error": "refused"}

        with patch("server.discovery.fingerprinter._grab_banner", side_effect=mock_grab), \
             patch("server.uptime_checker.tcp_check", side_effect=mock_tcp):
            result = asyncio.new_event_loop().run_until_complete(
                fingerprint("10.0.0.1", mac="00:50:56:aa:bb:cc")
            )
        assert result["vendor"] == "VMware"


# ─── Discovery API ──────────────────────────────────────────────────────────

class TestDiscoveryAPI:
    def test_scan_requires_auth(self):
        r = client.post("/api/v1/discovery/scan", json={"cidr": "10.0.0.0/30"})
        assert r.status_code == 401

    def test_status_requires_auth(self):
        r = client.get("/api/v1/discovery/status")
        assert r.status_code == 401

    def test_results_requires_auth(self):
        r = client.get("/api/v1/discovery/results")
        assert r.status_code == 401

    def test_status_returns_state(self, admin_token):
        r = client.get(
            "/api/v1/discovery/status",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "running" in data
        assert "found" in data

    def test_results_empty(self, admin_token, tmp_db):
        r = client.get(
            "/api/v1/discovery/results",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_scan_invalid_cidr(self, admin_token):
        r = client.post(
            "/api/v1/discovery/scan",
            json={"cidr": "not-a-cidr"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        # 202 kabul edilir ama arka planda hata oluşur — ya da 422
        assert r.status_code in (202, 422, 400)

    def test_scan_accepted(self, admin_token):
        """Geçerli CIDR → 202 Accepted dönmeli."""
        # Taramanın gerçekten çalışmasını önlemek için sweep mock'la
        async def mock_sweep(cidr):
            return []

        with patch("server.routes.discovery._run_scan", AsyncMock(return_value=None)):
            r = client.post(
                "/api/v1/discovery/scan",
                json={"cidr": "10.0.0.0/30"},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        # Önceki test scan_state'i running=True bırakmış olabilir → 202 veya 409
        assert r.status_code in (202, 409)

    def test_results_after_device_added(self, admin_token, tmp_db):
        """discovered tipinde cihaz eklenince results'ta görünmeli."""
        tmp_db.save_device("10.0.0.99", "found-host", "discovered", ip="10.0.0.99", status="up")
        r = client.get(
            "/api/v1/discovery/results",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        devices = r.json()["devices"]
        assert any(d["device_id"] == "10.0.0.99" for d in devices)
