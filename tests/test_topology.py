"""
Topology Engine testleri.
"""

import asyncio
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

from server.main import app
from server.topology.builder import (
    build_topology, _subnet_edges, _valid_ip,
)

client = TestClient(app)


# ─── Yardımcı fonksiyonlar ──────────────────────────────────────────────────

class TestValidIp:
    def test_valid(self):
        assert _valid_ip("192.168.1.1") is True
        assert _valid_ip("10.0.0.1") is True

    def test_invalid(self):
        assert _valid_ip("not-an-ip") is False
        assert _valid_ip("") is False
        assert _valid_ip("999.0.0.1") is False


class TestSubnetEdges:
    def test_same_subnet_gets_edge(self):
        devices = [
            {"device_id": "A", "ip": "192.168.1.10"},
            {"device_id": "B", "ip": "192.168.1.20"},
        ]
        edges = _subnet_edges(devices)
        assert len(edges) == 1
        assert set(edges[0]) == {"A", "B"}

    def test_different_subnets_no_edge(self):
        devices = [
            {"device_id": "A", "ip": "192.168.1.10"},
            {"device_id": "B", "ip": "10.0.0.1"},
        ]
        edges = _subnet_edges(devices)
        assert edges == []

    def test_single_device_no_edge(self):
        devices = [{"device_id": "A", "ip": "192.168.1.1"}]
        assert _subnet_edges(devices) == []

    def test_no_ip_skipped(self):
        devices = [
            {"device_id": "A", "ip": ""},
            {"device_id": "B", "ip": "192.168.1.1"},
        ]
        assert _subnet_edges(devices) == []

    def test_three_same_subnet(self):
        devices = [
            {"device_id": "A", "ip": "10.0.0.1"},
            {"device_id": "B", "ip": "10.0.0.2"},
            {"device_id": "C", "ip": "10.0.0.3"},
        ]
        edges = _subnet_edges(devices)
        # A anchor → B ve C ile bağlanır
        assert len(edges) == 2

    def test_edges_are_canonical(self):
        """Kenar src_id < dst_id sıralı olmalı."""
        devices = [
            {"device_id": "Z", "ip": "10.0.0.1"},
            {"device_id": "A", "ip": "10.0.0.2"},
        ]
        edges = _subnet_edges(devices)
        assert len(edges) == 1
        src, dst = edges[0]
        assert src <= dst


# ─── Database Topology Metodları ────────────────────────────────────────────

class TestTopologyDB:
    def test_upsert_and_get_node(self, tmp_db):
        tmp_db.upsert_topology_node("dev-1", "router", ip="10.0.0.1", device_type="snmp")
        graph = tmp_db.get_topology_graph()
        assert len(graph["nodes"]) == 1
        assert graph["nodes"][0]["device_id"] == "dev-1"
        assert graph["nodes"][0]["ip"] == "10.0.0.1"

    def test_upsert_node_updates_existing(self, tmp_db):
        tmp_db.upsert_topology_node("dev-1", "router", ip="10.0.0.1")
        tmp_db.upsert_topology_node("dev-1", "core-router", ip="10.0.0.1")
        graph = tmp_db.get_topology_graph()
        assert len(graph["nodes"]) == 1
        assert graph["nodes"][0]["name"] == "core-router"

    def test_upsert_edge(self, tmp_db):
        tmp_db.upsert_topology_node("A", "host-a", ip="10.0.0.1")
        tmp_db.upsert_topology_node("B", "host-b", ip="10.0.0.2")
        tmp_db.upsert_topology_edge("A", "B", "ip", "arp")
        graph = tmp_db.get_topology_graph()
        assert len(graph["edges"]) == 1

    def test_edge_is_canonical(self, tmp_db):
        """A→B ve B→A aynı kenar olmalı."""
        tmp_db.upsert_topology_node("A", "a", ip="10.0.0.1")
        tmp_db.upsert_topology_node("B", "b", ip="10.0.0.2")
        tmp_db.upsert_topology_edge("A", "B")
        tmp_db.upsert_topology_edge("B", "A")
        graph = tmp_db.get_topology_graph()
        assert len(graph["edges"]) == 1

    def test_clear_topology(self, tmp_db):
        tmp_db.upsert_topology_node("A", "a", ip="10.0.0.1")
        tmp_db.upsert_topology_edge("A", "A")
        tmp_db.clear_topology()
        graph = tmp_db.get_topology_graph()
        assert graph["nodes"] == []
        assert graph["edges"] == []

    def test_empty_graph(self, tmp_db):
        graph = tmp_db.get_topology_graph()
        assert graph == {"nodes": [], "edges": []}


# ─── Build Topology ─────────────────────────────────────────────────────────

class TestBuildTopology:
    def test_no_devices_builds_empty(self, tmp_db):
        """Kayıtlı cihaz yoksa boş topoloji."""
        with patch("server.database.db", tmp_db):
            result = asyncio.new_event_loop().run_until_complete(build_topology())
        assert result["nodes"] == 0
        assert result["edges"] == 0

    def test_devices_become_nodes(self, tmp_db):
        """Kayıtlı cihazlar node olarak eklenmeli."""
        tmp_db.save_device("10.0.0.1", "router", "snmp", ip="10.0.0.1", status="up")
        tmp_db.save_device("10.0.0.2", "server", "agent", ip="10.0.0.2", status="up")

        with patch("server.database.db", tmp_db), \
             patch("server.topology.builder._walk_arp", AsyncMock(return_value=[])), \
             patch("server.topology.builder._walk_lldp", AsyncMock(return_value=[])):
            result = asyncio.new_event_loop().run_until_complete(build_topology())

        assert result["nodes"] == 2

    def test_subnet_fallback_creates_edges(self, tmp_db):
        """ARP/LLDP yoksa subnet çıkarımı kenar oluşturmalı."""
        tmp_db.save_device("10.0.0.1", "dev-a", "discovered", ip="10.0.0.1", status="up")
        tmp_db.save_device("10.0.0.2", "dev-b", "discovered", ip="10.0.0.2", status="up")

        with patch("server.database.db", tmp_db), \
             patch("server.topology.builder._walk_arp", AsyncMock(return_value=[])), \
             patch("server.topology.builder._walk_lldp", AsyncMock(return_value=[])):
            result = asyncio.new_event_loop().run_until_complete(build_topology())

        assert result["edges"] >= 1

    def test_arp_creates_edges(self, tmp_db):
        """ARP tablosundan dönen komşu → kenar oluşturulmalı."""
        tmp_db.save_device("10.0.0.1", "router", "snmp", ip="10.0.0.1",
                           snmp_community="public", status="up")
        tmp_db.save_device("10.0.0.2", "server", "agent", ip="10.0.0.2", status="up")

        async def mock_arp(host, community):
            return [("10.0.0.2", "aa:bb:cc:dd:ee:ff")]

        with patch("server.database.db", tmp_db), \
             patch("server.topology.builder._walk_arp", side_effect=mock_arp), \
             patch("server.topology.builder._walk_lldp", AsyncMock(return_value=[])):
            result = asyncio.new_event_loop().run_until_complete(build_topology())

        assert result["edges"] >= 1


# ─── Topology API ────────────────────────────────────────────────────────────

class TestTopologyAPI:
    def test_graph_requires_auth(self):
        r = client.get("/api/v1/topology/graph")
        assert r.status_code == 401

    def test_refresh_requires_auth(self):
        r = client.post("/api/v1/topology/refresh")
        assert r.status_code == 401

    def test_graph_empty(self, admin_token, tmp_db):
        r = client.get(
            "/api/v1/topology/graph",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "nodes" in data
        assert "edges" in data
        assert data["node_count"] == 0

    def test_refresh_accepted(self, admin_token):
        with patch("server.topology.builder.build_topology", AsyncMock(return_value={"nodes": 0, "edges": 0})):
            r = client.post(
                "/api/v1/topology/refresh",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert r.status_code in (202, 409)

    def test_graph_after_node_added(self, admin_token, tmp_db):
        """Node eklendikten sonra graph endpoint'i göstermeli."""
        tmp_db.upsert_topology_node("10.0.0.1", "test-router", ip="10.0.0.1")
        r = client.get(
            "/api/v1/topology/graph",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["node_count"] == 1
