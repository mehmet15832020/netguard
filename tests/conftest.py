"""
Pytest paylaşımlı fixture'ları.

session scope → tüm test süresince bir kez çalışır.
Token direkt oluşturulur — rate limited /auth/login endpoint'i çağrılmaz.
"""

import os

import pytest
from server.auth import create_access_token
from server.database import DatabaseManager

_PG_TRUNCATE_TABLES = [
    "blocked_ips", "fp_rules", "asset_baselines", "attack_chain_state",
    "incident_events", "incidents", "topology_edges", "topology_nodes",
    "token_blacklist", "threat_intel_cache", "audit_log", "api_keys",
    "service_checks", "snmp_poll_history", "snmp_devices", "devices",
    "correlated_events", "normalized_logs", "raw_logs",
    "security_events", "alerts", "db_users", "sites",
]


@pytest.fixture(scope="session")
def admin_token() -> str:
    """Admin JWT token'ını direkt oluştur (rate limit'i tetiklemez)."""
    return create_access_token(username="admin", role="admin", tenant_id="default")


@pytest.fixture(scope="session")
def superadmin_token() -> str:
    """Superadmin JWT token — tüm tenant'lara erişir."""
    return create_access_token(username="admin", role="superadmin", tenant_id=None)



@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Her test için ayrı SQLite DB — tüm test modülleri kullanabilir."""
    db_file = str(tmp_path / "test.db")
    test_db = DatabaseManager(db_path=db_file)
    monkeypatch.setattr("server.database.db", test_db)
    monkeypatch.setattr("server.routes.devices.db", test_db)
    monkeypatch.setattr("server.routes.agents.db", test_db)
    monkeypatch.setattr("server.routes.snmp.db", test_db)
    monkeypatch.setattr("server.routes.discovery.db", test_db)
    monkeypatch.setattr("server.routes.topology.db", test_db)
    monkeypatch.setattr("server.routes.incidents.db", test_db)
    monkeypatch.setattr("server.routes.tenants.db", test_db)
    monkeypatch.setattr("server.incident_enricher.db", test_db)
    monkeypatch.setattr("server.routes.network_intel.db", test_db)
    monkeypatch.setattr("server.routes.active_response.db", test_db)
    return test_db


# ── PostgreSQL / TimescaleDB fixtures (testcontainers) ────────────────────────

@pytest.fixture(scope="session")
def pg_container():
    """TimescaleDB Docker container — session boyunca bir kez başlar, Alembic migrate eder."""
    try:
        from testcontainers.postgres import PostgresContainer
        import docker
        docker.from_env().ping()
    except ImportError:
        pytest.skip("testcontainers paketi yüklü değil")
    except Exception:
        pytest.skip("Docker daemon erişilemiyor — pg testleri atlanıyor")

    with PostgresContainer(
        image="timescale/timescaledb:latest-pg16",
        username="netguard",
        password="netguard_test",
        dbname="netguard_test",
    ) as pg:
        url = pg.get_connection_url().replace("+psycopg2", "")

        from alembic.config import Config
        from alembic import command as alembic_command

        prev = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = url
        try:
            cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
            alembic_command.upgrade(cfg, "head")
        finally:
            if prev is None:
                os.environ.pop("DATABASE_URL", None)
            else:
                os.environ["DATABASE_URL"] = prev

        pg._netguard_url = url
        yield pg


@pytest.fixture
def pg_db(pg_container, monkeypatch):
    """Her test için izole PostgreSQL DB — testcontainers TimescaleDB."""
    from server.database_pg import DatabaseManager as PgManager

    test_db = PgManager(pg_container._netguard_url)

    monkeypatch.setattr("server.database.db", test_db)
    monkeypatch.setattr("server.routes.devices.db", test_db)
    monkeypatch.setattr("server.routes.agents.db", test_db)
    monkeypatch.setattr("server.routes.snmp.db", test_db)
    monkeypatch.setattr("server.routes.discovery.db", test_db)
    monkeypatch.setattr("server.routes.topology.db", test_db)
    monkeypatch.setattr("server.routes.incidents.db", test_db)
    monkeypatch.setattr("server.routes.tenants.db", test_db)
    monkeypatch.setattr("server.incident_enricher.db", test_db)

    tables = ", ".join(_PG_TRUNCATE_TABLES)
    with test_db._connect() as conn:
        conn.execute(f"TRUNCATE {tables} RESTART IDENTITY CASCADE")
        conn.execute("INSERT INTO tenants (id, name) VALUES ('default', 'Default') ON CONFLICT DO NOTHING")

    yield test_db
    test_db._pool.close()
