"""
T4-3 Multi-tenant testleri.

Kapsam:
- Tenant CRUD (superadmin)
- Site CRUD (admin)
- Kullanıcı CRUD (admin)
- Tenant izolasyonu: admin kendi tenant'ını görür, diğerini göremez
- Superadmin tüm tenant'ları görür
"""

import pytest
from fastapi.testclient import TestClient
from server.main import app

client = TestClient(app, raise_server_exceptions=True)


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── Tenant CRUD ──────────────────────────────────────────────────

class TestTenantCRUD:

    def test_list_tenants_superadmin(self, superadmin_token, tmp_db):
        r = client.get("/api/v1/tenants", headers=_auth(superadmin_token))
        assert r.status_code == 200
        ids = [t["id"] for t in r.json()["tenants"]]
        assert "default" in ids

    def test_list_tenants_admin_sees_only_own(self, admin_token, tmp_db):
        r = client.get("/api/v1/tenants", headers=_auth(admin_token))
        assert r.status_code == 200
        # admin_token tenant_id="default" → sadece default tenant
        assert all(t["id"] == "default" for t in r.json()["tenants"])

    def test_create_tenant_superadmin(self, superadmin_token, tmp_db):
        r = client.post(
            "/api/v1/tenants",
            json={"id": "acme-corp", "name": "Acme Corp"},
            headers=_auth(superadmin_token),
        )
        assert r.status_code == 201
        assert r.json()["tenant"]["id"] == "acme-corp"

    def test_create_tenant_duplicate_fails(self, superadmin_token, tmp_db):
        client.post("/api/v1/tenants", json={"id": "dup-test", "name": "Dup"}, headers=_auth(superadmin_token))
        r = client.post("/api/v1/tenants", json={"id": "dup-test", "name": "Dup2"}, headers=_auth(superadmin_token))
        assert r.status_code == 409

    def test_create_tenant_invalid_id(self, superadmin_token, tmp_db):
        r = client.post(
            "/api/v1/tenants",
            json={"id": "BÜYÜK HARF", "name": "Bad"},
            headers=_auth(superadmin_token),
        )
        assert r.status_code == 422

    def test_create_tenant_forbidden_for_admin(self, admin_token, tmp_db):
        r = client.post(
            "/api/v1/tenants",
            json={"id": "new-tenant", "name": "New"},
            headers=_auth(admin_token),
        )
        assert r.status_code == 403

    def test_get_tenant(self, superadmin_token, tmp_db):
        r = client.get("/api/v1/tenants/default", headers=_auth(superadmin_token))
        assert r.status_code == 200
        assert r.json()["id"] == "default"

    def test_get_tenant_not_found(self, superadmin_token, tmp_db):
        r = client.get("/api/v1/tenants/ghost", headers=_auth(superadmin_token))
        assert r.status_code == 404

    def test_patch_tenant(self, superadmin_token, tmp_db):
        client.post("/api/v1/tenants", json={"id": "patch-me", "name": "Old"}, headers=_auth(superadmin_token))
        r = client.patch("/api/v1/tenants/patch-me", json={"name": "New Name"}, headers=_auth(superadmin_token))
        assert r.status_code == 200
        assert r.json()["tenant"]["name"] == "New Name"

    def test_delete_default_tenant_forbidden(self, superadmin_token, tmp_db):
        r = client.delete("/api/v1/tenants/default", headers=_auth(superadmin_token))
        assert r.status_code == 400

    def test_delete_tenant(self, superadmin_token, tmp_db):
        client.post("/api/v1/tenants", json={"id": "del-me", "name": "Del"}, headers=_auth(superadmin_token))
        r = client.delete("/api/v1/tenants/del-me", headers=_auth(superadmin_token))
        assert r.status_code == 200
        assert client.get("/api/v1/tenants/del-me", headers=_auth(superadmin_token)).status_code == 404


# ── Site CRUD ────────────────────────────────────────────────────

class TestSiteCRUD:

    def _setup_tenant(self, token: str, tenant_id: str = "test-sites") -> None:
        client.post(
            "/api/v1/tenants",
            json={"id": tenant_id, "name": "Test Sites Tenant"},
            headers=_auth(token),
        )

    def test_create_and_list_sites(self, superadmin_token, tmp_db):
        self._setup_tenant(superadmin_token, "site-tenant")
        r = client.post(
            "/api/v1/tenants/site-tenant/sites",
            json={"id": "site-a", "name": "Site A", "location": "Istanbul"},
            headers=_auth(superadmin_token),
        )
        assert r.status_code == 201
        r2 = client.get("/api/v1/tenants/site-tenant/sites", headers=_auth(superadmin_token))
        assert r2.status_code == 200
        site_ids = [s["id"] for s in r2.json()["sites"]]
        assert "site-a" in site_ids
        assert "site-tenant-main" in site_ids  # otomatik oluşturulan

    def test_create_site_duplicate_fails(self, superadmin_token, tmp_db):
        self._setup_tenant(superadmin_token, "dup-sites")
        client.post("/api/v1/tenants/dup-sites/sites", json={"id": "s1", "name": "S1"}, headers=_auth(superadmin_token))
        r = client.post("/api/v1/tenants/dup-sites/sites", json={"id": "s1", "name": "S1b"}, headers=_auth(superadmin_token))
        assert r.status_code == 409

    def test_delete_site(self, superadmin_token, tmp_db):
        self._setup_tenant(superadmin_token, "del-site-tenant")
        client.post("/api/v1/tenants/del-site-tenant/sites", json={"id": "del-site", "name": "Del"}, headers=_auth(superadmin_token))
        r = client.delete("/api/v1/tenants/del-site-tenant/sites/del-site", headers=_auth(superadmin_token))
        assert r.status_code == 200


# ── Kullanıcı CRUD ───────────────────────────────────────────────

class TestUserCRUD:

    def _setup(self, token: str, tenant_id: str = "user-tenant") -> None:
        client.post(
            "/api/v1/tenants",
            json={"id": tenant_id, "name": "User Tenant"},
            headers=_auth(token),
        )

    def test_create_and_list_user(self, superadmin_token, tmp_db):
        self._setup(superadmin_token)
        r = client.post(
            "/api/v1/tenants/user-tenant/users",
            json={"username": "alice", "password": "password123", "role": "viewer"},
            headers=_auth(superadmin_token),
        )
        assert r.status_code == 201
        r2 = client.get("/api/v1/tenants/user-tenant/users", headers=_auth(superadmin_token))
        assert any(u["username"] == "alice" for u in r2.json()["users"])

    def test_create_user_short_password(self, superadmin_token, tmp_db):
        self._setup(superadmin_token, "pw-tenant")
        r = client.post(
            "/api/v1/tenants/pw-tenant/users",
            json={"username": "bob", "password": "short", "role": "viewer"},
            headers=_auth(superadmin_token),
        )
        assert r.status_code == 422

    def test_create_user_invalid_role(self, superadmin_token, tmp_db):
        self._setup(superadmin_token, "role-tenant")
        r = client.post(
            "/api/v1/tenants/role-tenant/users",
            json={"username": "carol", "password": "password123", "role": "superadmin"},
            headers=_auth(superadmin_token),
        )
        assert r.status_code == 422

    def test_update_user_role(self, superadmin_token, tmp_db):
        self._setup(superadmin_token, "update-tenant")
        client.post(
            "/api/v1/tenants/update-tenant/users",
            json={"username": "dave", "password": "password123", "role": "viewer"},
            headers=_auth(superadmin_token),
        )
        r = client.patch(
            "/api/v1/tenants/update-tenant/users/dave",
            json={"role": "admin"},
            headers=_auth(superadmin_token),
        )
        assert r.status_code == 200
        users = client.get("/api/v1/tenants/update-tenant/users", headers=_auth(superadmin_token)).json()["users"]
        dave = next(u for u in users if u["username"] == "dave")
        assert dave["role"] == "admin"

    def test_delete_user(self, superadmin_token, tmp_db):
        self._setup(superadmin_token, "del-user-tenant")
        client.post(
            "/api/v1/tenants/del-user-tenant/users",
            json={"username": "eve", "password": "password123", "role": "viewer"},
            headers=_auth(superadmin_token),
        )
        r = client.delete("/api/v1/tenants/del-user-tenant/users/eve", headers=_auth(superadmin_token))
        assert r.status_code == 200
        users = client.get("/api/v1/tenants/del-user-tenant/users", headers=_auth(superadmin_token)).json()["users"]
        assert not any(u["username"] == "eve" for u in users)

    def test_delete_nonexistent_user(self, superadmin_token, tmp_db):
        self._setup(superadmin_token, "ghost-tenant")
        r = client.delete("/api/v1/tenants/ghost-tenant/users/ghost", headers=_auth(superadmin_token))
        assert r.status_code == 404


# ── Tenant izolasyonu ────────────────────────────────────────────

class TestTenantIsolation:
    """Admin yalnızca kendi tenant'ının datasını görür."""

    def test_admin_cannot_access_other_tenant(self, admin_token, superadmin_token, tmp_db):
        """admin_token tenant_id='default', acme-corp tenant'ına erişemez."""
        client.post(
            "/api/v1/tenants",
            json={"id": "acme-isolation", "name": "Acme"},
            headers=_auth(superadmin_token),
        )
        r = client.get("/api/v1/tenants/acme-isolation/sites", headers=_auth(admin_token))
        assert r.status_code == 403

    def test_superadmin_can_access_any_tenant(self, superadmin_token, tmp_db):
        client.post(
            "/api/v1/tenants",
            json={"id": "any-tenant", "name": "Any"},
            headers=_auth(superadmin_token),
        )
        r = client.get("/api/v1/tenants/any-tenant/sites", headers=_auth(superadmin_token))
        assert r.status_code == 200

    def test_db_tenant_filter_devices(self, tmp_db):
        """DB seviyesinde filtre: farklı tenant'ların cihazları karışmaz."""
        tmp_db.save_device("dev-default", "Router-Default", "snmp", tenant_id="default")
        tmp_db.save_device("dev-acme", "Router-Acme", "snmp", tenant_id="acme")

        default_devices = tmp_db.get_devices(tenant_id="default")
        acme_devices    = tmp_db.get_devices(tenant_id="acme")

        assert any(d["device_id"] == "dev-default" for d in default_devices)
        assert not any(d["device_id"] == "dev-acme" for d in default_devices)

        assert any(d["device_id"] == "dev-acme" for d in acme_devices)
        assert not any(d["device_id"] == "dev-default" for d in acme_devices)

    def test_superadmin_scope_returns_all(self, tmp_db):
        """tenant_id=None (superadmin scope) tüm cihazları döner."""
        tmp_db.save_device("sa-dev-1", "SA-Dev-1", "snmp", tenant_id="alpha")
        tmp_db.save_device("sa-dev-2", "SA-Dev-2", "snmp", tenant_id="beta")

        all_devices = tmp_db.get_devices(tenant_id=None)
        ids = [d["device_id"] for d in all_devices]
        assert "sa-dev-1" in ids
        assert "sa-dev-2" in ids

    def test_db_tenant_filter_incidents(self, tmp_db):
        """Incident izolasyonu: farklı tenant'lar birbirinin incident'larını göremez."""
        from shared.models import Incident, IncidentStatus
        inc_a = Incident(
            incident_id="inc-a", title="A", severity="warning",
            status=IncidentStatus.OPEN, created_by="admin",
        )
        inc_b = Incident(
            incident_id="inc-b", title="B", severity="critical",
            status=IncidentStatus.OPEN, created_by="admin",
        )
        tmp_db.create_incident(inc_a, tenant_id="tenant-a")
        tmp_db.create_incident(inc_b, tenant_id="tenant-b")

        a_incidents = tmp_db.get_incidents(tenant_id="tenant-a")
        b_incidents = tmp_db.get_incidents(tenant_id="tenant-b")

        assert all(i["incident_id"] == "inc-a" for i in a_incidents)
        assert all(i["incident_id"] == "inc-b" for i in b_incidents)
