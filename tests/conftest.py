"""
Pytest paylaşımlı fixture'ları.

session scope → tüm test süresince bir kez çalışır.
Token direkt oluşturulur — rate limited /auth/login endpoint'i çağrılmaz.
"""

import os

import pytest
from server.auth import create_access_token

_PG_TRUNCATE_TABLES = [
    "blocked_ips", "fp_rules", "asset_baselines", "attack_chain_state",
    "incident_events", "incidents", "topology_edges", "topology_nodes",
    "token_blacklist", "threat_intel_cache", "audit_log", "api_keys",
    "service_checks", "snmp_poll_history", "snmp_devices", "devices",
    "correlated_events", "normalized_logs", "raw_logs",
    "security_events", "alerts", "db_users", "sites", "tenants",
    "alert_explanations",
]


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Her test öncesinde shared limiter storage'ını sıfırla — test izolasyonu."""
    try:
        from server.limiter import limiter
        limiter._storage.reset()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _reset_attack_chain_tracker():
    """Her test öncesinde attack_chain_tracker._chains sıfırla — singleton state izolasyonu."""
    try:
        from server.attack_chain import attack_chain_tracker
        with attack_chain_tracker._lock:
            attack_chain_tracker._chains.clear()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _reset_logging_state():
    """Her test öncesinde logging durumunu sıfırla.

    Bazı testler TestClient(app) üzerinden uvicorn logging config'ini tetikler;
    bu bazı logger'ların disabled bayrağını True yapar.
    Bu durum caplog tabanlı testleri (test_attack_chain, test_correlator) bozar.
    """
    import logging
    root = logging.getLogger()
    for _logger in root.manager.loggerDict.values():
        if isinstance(_logger, logging.Logger):
            _logger.disabled = False
    yield


@pytest.fixture(scope="session")
def admin_token() -> str:
    """Admin JWT token'ını direkt oluştur (rate limit'i tetiklemez)."""
    return create_access_token(username="admin", role="admin", tenant_id="default")


@pytest.fixture(scope="session")
def superadmin_token() -> str:
    """Superadmin JWT token — tüm tenant'lara erişir."""
    return create_access_token(username="admin", role="superadmin", tenant_id=None)


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
        pytest.skip("Docker daemon erişilemiyor — testler atlanıyor")

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


def _make_test_db(url: str, monkeypatch):
    """URL'den test DatabaseManager oluştur, tüm DB referanslarını monkeypatch et."""
    from server.database import DatabaseManager
    test_db = DatabaseManager(url)

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
    monkeypatch.setattr("server.routes.mitre.db", test_db)
    monkeypatch.setattr("server.routes.analytics.db", test_db)
    monkeypatch.setattr("server.log_store._db", test_db)
    monkeypatch.setattr("server.anomaly.engine._netguard_db", test_db)
    monkeypatch.setattr("server.routes.correlation.db", test_db)
    monkeypatch.setattr("server.routes.security.db", test_db)
    monkeypatch.setattr("server.routes.logs.db", test_db)
    monkeypatch.setattr("server.routes.assets.db", test_db)
    monkeypatch.setattr("server.routes.maintenance.db", test_db)
    monkeypatch.setattr("server.routes.alerts.db", test_db)
    monkeypatch.setattr("server.routes.evtx.db", test_db)
    monkeypatch.setattr("server.routes.fp_rules.db", test_db)
    monkeypatch.setattr("server.routes.compliance.db", test_db)
    monkeypatch.setattr("server.routes.sigma.db", test_db)
    monkeypatch.setattr("server.routes.mitre.db", test_db)
    monkeypatch.setattr("server.asset_baseline.db", test_db)
    monkeypatch.setattr("server.config_monitor.db", test_db)
    monkeypatch.setattr("server.port_monitor.db", test_db)
    monkeypatch.setattr("server.security_log_parser.db", test_db)
    monkeypatch.setattr("server.log_normalizer.db", test_db)
    monkeypatch.setattr("server.correlator.db", test_db)
    monkeypatch.setattr("server.retention.db", test_db)
    monkeypatch.setattr("server.detectors.beaconing.db", test_db)
    monkeypatch.setattr("server.detectors.manager.db", test_db)

    tables = ", ".join(_PG_TRUNCATE_TABLES)
    with test_db._connect() as conn:
        conn.execute(f"TRUNCATE {tables} RESTART IDENTITY CASCADE")
        conn.execute(
            "INSERT INTO tenants (id, name) VALUES ('default', 'Default') ON CONFLICT DO NOTHING"
        )

    return test_db


@pytest.fixture
def tmp_db(pg_container, monkeypatch):
    """Her test için izole PostgreSQL DB — testcontainers TimescaleDB."""
    test_db = _make_test_db(pg_container._netguard_url, monkeypatch)
    yield test_db
    test_db._pool.close()


@pytest.fixture
def pg_db(pg_container, monkeypatch):
    """Her test için izole PostgreSQL DB — testcontainers TimescaleDB (pg_db alias)."""
    test_db = _make_test_db(pg_container._netguard_url, monkeypatch)
    yield test_db
    test_db._pool.close()


@pytest.fixture
def mem_db(pg_container):
    """normalized_logs tablosu olan izole PostgreSQL bağlantısı — sigma_executor için."""
    import psycopg
    from psycopg.rows import dict_row
    conn = psycopg.connect(
        pg_container._netguard_url,
        row_factory=dict_row,
        options="-c timezone=UTC",
    )
    conn.execute("TRUNCATE normalized_logs")
    conn.commit()
    yield conn
    try:
        conn.rollback()
    except Exception:
        pass
    conn.close()
