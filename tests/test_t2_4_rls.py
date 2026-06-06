"""T2-4 — PostgreSQL Row Level Security testleri.

RLS politikasının tenant_id izolasyonunu sağladığını doğrular.

Kaynak: PostgreSQL RLS §5.8, CIS PostgreSQL Benchmark §6.2,
        NIST SP 800-162 (ABAC), OWASP ASVS §4.1.3, PCI DSS §7.2

Not: RLS superuser'ları atlar (PostgreSQL dokümantasyonu). İzolasyon
testleri için ayrı non-superuser test rolü kullanılır.
"""

import uuid
from contextlib import contextmanager

import psycopg
import pytest
from psycopg.rows import dict_row

_RLS_TABLES = [
    # normalized_logs: TimescaleDB hypertable (compression) — RLS desteklenmiyor
    # audit_log: tenant_id kolonu yok — global log
    "alerts",
    "incidents",
    "blocked_ips",
    "asset_baselines",
    "correlated_events",
    "alert_explanations",
    "attack_chain_state",
    "devices",
    "fp_rules",
    "saved_hunts",
    "security_events",
]

_APP_ROLE = "ng_rls_tester"


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def rls_role(pg_container):
    """Non-superuser PostgreSQL rolü — gerçek RLS testi için."""
    url = pg_container._netguard_url
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f"DROP ROLE IF EXISTS {_APP_ROLE}")
        admin.execute(f"CREATE ROLE {_APP_ROLE} LOGIN PASSWORD 'rls_test_pw'")
        admin.execute(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {_APP_ROLE}"
        )
        admin.execute(
            f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {_APP_ROLE}"
        )

    yield url

    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f"DROP OWNED BY {_APP_ROLE}")
        admin.execute(f"DROP ROLE IF EXISTS {_APP_ROLE}")


def _app_url(base_url: str) -> str:
    """Base URL'yi ng_rls_tester kullanıcısı için dönüştür."""
    # postgresql://netguard:netguard_test@host:port/db
    import re
    return re.sub(r"//[^@]+@", f"//{_APP_ROLE}:rls_test_pw@", base_url)


@contextmanager
def _app_connect(url: str):
    """Non-superuser bağlantısı — RLS aktif."""
    with psycopg.connect(_app_url(url), row_factory=dict_row, autocommit=False) as conn:
        yield conn


@contextmanager
def _app_connect_as_tenant(url: str, tenant_id: str):
    """Non-superuser + tenant bağlamı — RLS tam izolasyon."""
    with psycopg.connect(_app_url(url), row_factory=dict_row, autocommit=False) as conn:
        conn.execute("SELECT set_config('app.current_tenant', %s, true)", [tenant_id])
        yield conn


def _insert_alert(conn, tenant_id: str, hostname: str = "host") -> str:
    alert_id = str(uuid.uuid4())
    agent_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO alerts
            (alert_id, agent_id, hostname, severity, status, metric, message,
             value, threshold, triggered_at, tenant_id)
        VALUES (%s, %s, %s, 'info', 'active', 'cpu', 'msg', 1.0, 80.0, NOW(), %s)
        """,
        [alert_id, agent_id, hostname, tenant_id],
    )
    return alert_id


def _insert_blocked_ip(conn, tenant_id: str, ip: str = "1.2.3.4") -> None:
    block_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO blocked_ips (block_id, ip, reason, blocked_by, tenant_id)
        VALUES (%s, %s, 'test', 'admin', %s)
        ON CONFLICT DO NOTHING
        """,
        [block_id, ip, tenant_id],
    )


# ─── RLS Yapısı ──────────────────────────────────────────────────────────────


class TestRLSEnabled:

    def test_rls_enabled_on_all_required_tables(self, tmp_db):
        with tmp_db._connect() as conn:
            rows = conn.execute(
                """
                SELECT relname, relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relname = ANY(%s) AND relkind = 'r'
                ORDER BY relname
                """,
                [_RLS_TABLES],
            ).fetchall()

        found = {r["relname"] for r in rows}
        for table in _RLS_TABLES:
            assert table in found, f"Tablo bulunamadı: {table}"
            row = next(r for r in rows if r["relname"] == table)
            assert row["relrowsecurity"], f"RLS aktif değil: {table}"
            assert row["relforcerowsecurity"], f"FORCE RLS aktif değil: {table}"

    def test_tenant_isolation_policy_exists_on_all_tables(self, tmp_db):
        with tmp_db._connect() as conn:
            rows = conn.execute(
                """
                SELECT tablename, policyname
                FROM pg_policies
                WHERE tablename = ANY(%s) AND policyname = 'tenant_isolation'
                """,
                [_RLS_TABLES],
            ).fetchall()

        found = {r["tablename"] for r in rows}
        for table in _RLS_TABLES:
            assert table in found, f"tenant_isolation policy eksik: {table}"

    def test_policy_allows_null_context(self, tmp_db):
        """Policy USING ifadesi: NULL context → tüm satırlara erişim."""
        with tmp_db._connect() as conn:
            rows = conn.execute(
                """
                SELECT qual FROM pg_policies
                WHERE tablename = 'alerts' AND policyname = 'tenant_isolation'
                """
            ).fetchall()
        assert rows, "alerts policy bulunamadı"
        qual = rows[0]["qual"]
        assert "current_setting" in qual
        assert "tenant_id" in qual


# ─── _connect_as_tenant API ──────────────────────────────────────────────────


class TestConnectAsTenant:

    def test_connect_as_tenant_sets_local(self, tmp_db):
        with tmp_db._connect_as_tenant("my_tenant") as conn:
            row = conn.execute(
                "SELECT current_setting('app.current_tenant', true) AS t"
            ).fetchone()
        assert row["t"] == "my_tenant"

    def test_connect_as_tenant_returns_null_after_exit(self, tmp_db):
        """Transaction bittikten sonra context temizlenir."""
        with tmp_db._connect_as_tenant("alpha") as conn:
            pass

        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT current_setting('app.current_tenant', true) AS t"
            ).fetchone()
        assert row["t"] is None or row["t"] == ""

    def test_no_context_shows_null(self, tmp_db):
        """Context set edilmeden current_setting NULL döner."""
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT current_setting('app.current_tenant', true) AS t"
            ).fetchone()
        assert row["t"] is None or row["t"] == ""


# ─── RLS İzolasyon (Non-Superuser) ───────────────────────────────────────────


class TestRLSIsolation:
    """Non-superuser bağlantısı ile gerçek RLS izolasyon testleri."""

    def test_no_context_sees_all_rows(self, tmp_db, rls_role):
        with tmp_db._connect() as conn:
            _insert_alert(conn, "tenant_a")
            _insert_alert(conn, "tenant_b")

        with _app_connect(rls_role) as conn:
            count = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]

        assert count == 2

    def test_tenant_context_restricts_to_own_rows(self, tmp_db, rls_role):
        with tmp_db._connect() as conn:
            id_a = _insert_alert(conn, "alpha")
            _insert_alert(conn, "beta")

        with _app_connect_as_tenant(rls_role, "alpha") as conn:
            rows = conn.execute("SELECT alert_id FROM alerts").fetchall()

        assert len(rows) == 1
        assert rows[0]["alert_id"] == id_a

    def test_tenant_b_cannot_see_tenant_a_data(self, tmp_db, rls_role):
        with tmp_db._connect() as conn:
            _insert_alert(conn, "tenant_a", hostname="host_a")
            _insert_alert(conn, "tenant_b", hostname="host_b")

        with _app_connect_as_tenant(rls_role, "tenant_b") as conn:
            rows = conn.execute("SELECT hostname FROM alerts").fetchall()

        hostnames = {r["hostname"] for r in rows}
        assert "host_a" not in hostnames
        assert "host_b" in hostnames

    def test_empty_string_context_sees_all_rows(self, tmp_db, rls_role):
        with tmp_db._connect() as conn:
            _insert_alert(conn, "alpha")
            _insert_alert(conn, "beta")

        with _app_connect(rls_role) as conn:
            conn.execute("SELECT set_config('app.current_tenant', '', true)")
            count = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]

        assert count == 2

    def test_context_resets_after_transaction(self, tmp_db, rls_role):
        with tmp_db._connect() as conn:
            _insert_alert(conn, "alpha")
            _insert_alert(conn, "beta")

        with _app_connect_as_tenant(rls_role, "alpha") as conn:
            count_in = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        assert count_in == 1

        with _app_connect(rls_role) as conn:
            count_out = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        assert count_out == 2

    def test_blocked_ips_tenant_isolation(self, tmp_db, rls_role):
        with tmp_db._connect() as conn:
            _insert_blocked_ip(conn, "tenant_a", "10.9.0.1")
            _insert_blocked_ip(conn, "tenant_b", "10.9.0.2")

        with _app_connect_as_tenant(rls_role, "tenant_a") as conn:
            rows = conn.execute("SELECT ip FROM blocked_ips").fetchall()

        ips = {r["ip"] for r in rows}
        assert "10.9.0.1" in ips
        assert "10.9.0.2" not in ips

    def test_three_tenants_isolated(self, tmp_db, rls_role):
        tenants = ["alpha_rls", "beta_rls", "gamma_rls"]
        inserted = {}

        with tmp_db._connect() as conn:
            for t in tenants:
                inserted[t] = _insert_alert(conn, t)

        for t in tenants:
            with _app_connect_as_tenant(rls_role, t) as conn:
                rows = conn.execute("SELECT alert_id FROM alerts").fetchall()
            # Only this tenant's row visible (plus possibly others from previous tests)
            ids = {r["alert_id"] for r in rows}
            assert inserted[t] in ids
            for other in tenants:
                if other != t:
                    assert inserted[other] not in ids

    def test_write_in_tenant_a_invisible_in_tenant_b(self, tmp_db, rls_role):
        with _app_connect_as_tenant(rls_role, "corp_rls_a") as conn:
            alert_id = _insert_alert(conn, "corp_rls_a")
            conn.commit()

        with _app_connect_as_tenant(rls_role, "corp_rls_b") as conn:
            row = conn.execute(
                "SELECT alert_id FROM alerts WHERE alert_id = %s", [alert_id]
            ).fetchone()

        assert row is None

    def test_default_tenant_isolation(self, tmp_db, rls_role):
        with tmp_db._connect() as conn:
            default_id = _insert_alert(conn, "default_rls")
            _insert_alert(conn, "other_rls")

        with _app_connect_as_tenant(rls_role, "default_rls") as conn:
            rows = conn.execute(
                "SELECT alert_id FROM alerts WHERE tenant_id IN ('default_rls', 'other_rls')"
            ).fetchall()

        assert len(rows) == 1
        assert rows[0]["alert_id"] == default_id
