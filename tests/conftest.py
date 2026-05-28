"""
Pytest paylaşımlı fixture'ları.

session scope → tüm test süresince bir kez çalışır.
Token direkt oluşturulur — rate limited /auth/login endpoint'i çağrılmaz.
"""

import contextlib
import os
import re
import sqlite3
from datetime import datetime

import pytest
from server.auth import create_access_token
from server.database import DatabaseManager

_PG_PLACEHOLDER_RE = re.compile(r"%s")
_PG_NOW_RE = re.compile(r"NOW\(\)\s*-\s*INTERVAL\s*'(\d+)\s*seconds?'", re.IGNORECASE)


class _PGCompatCursor:
    """SQLite cursor wrapper — psycopg3 %s placeholder'ları ?'ye çevirir."""

    def __init__(self, cursor):
        self._cur = cursor

    def _adapt(self, sql: str) -> str:
        return _PG_PLACEHOLDER_RE.sub("?", sql)

    def execute(self, sql: str, params=None):
        self._cur.execute(self._adapt(sql), params or [])
        return self

    def fetchall(self):
        rows = self._cur.fetchall()
        return rows

    def fetchone(self):
        return self._cur.fetchone()

    @property
    def rowcount(self):
        return self._cur.rowcount

    def __iter__(self):
        return iter(self._cur)


def _adapt_params(params):
    """datetime nesnelerini ISO string'e çevirir — SQLite 3.12 uyumluluğu."""
    if not params:
        return params
    adapted = []
    for p in params:
        if isinstance(p, datetime):
            adapted.append(p.isoformat())
        else:
            adapted.append(p)
    return adapted


class _PGCompatConn:
    """
    SQLite connection wrapper — %s placeholder'ları ?'ye çevirir.
    executescript gibi SQLite-specific metodlar ham connection'a yönlendirilir.
    """

    def __init__(self, conn):
        self._conn = conn

    @staticmethod
    def _adapt_sql(sql: str) -> str:
        sql = _PG_PLACEHOLDER_RE.sub("?", sql)
        sql = _PG_NOW_RE.sub(lambda m: f"datetime('now', '-{m.group(1)} seconds')", sql)
        sql = sql.replace(" ILIKE ", " LIKE ")
        sql = sql.replace("%%", "%")
        return sql

    def execute(self, sql: str, params=None):
        adapted = _adapt_params(params)
        return _PGCompatCursor(self._conn.execute(self._adapt_sql(sql), adapted or []))

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _sqlite_date_trunc(unit: str, value) -> str:
    """SQLite için PostgreSQL date_trunc() eşdeğeri."""
    if value is None:
        return None
    if isinstance(value, str):
        dt_str = value
    else:
        dt_str = str(value)
    try:
        from datetime import datetime, timezone
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(dt_str)
        if unit == "hour":
            return dt.replace(minute=0, second=0, microsecond=0).isoformat()
        if unit == "day":
            return dt.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        if unit == "month":
            return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        return dt_str
    except Exception:
        return dt_str


def _sqlite_to_char(value, fmt) -> str:
    """SQLite için PostgreSQL to_char() eşdeğeri — saatlik ISO format üretir."""
    if value is None:
        return None
    try:
        from datetime import datetime, timezone
        dt_str = str(value)
        if dt_str.endswith("Z"):
            dt_str = dt_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(dt_str).astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:00:00Z")
    except Exception:
        return str(value)


class _PGCompatDatabaseManager(DatabaseManager):
    """DatabaseManager subclass — _connect() PG-uyumlu wrapper döndürür."""

    @contextlib.contextmanager
    def _connect(self):
        raw = sqlite3.connect(self._path, check_same_thread=False)
        raw.execute("PRAGMA journal_mode=WAL")
        raw.execute("PRAGMA foreign_keys=ON")
        raw.row_factory = sqlite3.Row
        raw.create_function("date_trunc", 2, _sqlite_date_trunc)
        raw.create_function("to_char", 2, _sqlite_to_char)
        conn = _PGCompatConn(raw)
        try:
            yield conn
            raw.commit()
        except Exception:
            raw.rollback()
            raise
        finally:
            raw.close()


@pytest.fixture(autouse=True)
def _patch_sqlite_connect(monkeypatch):
    """
    Tüm testlerde DatabaseManager._connect()'i PG-uyumlu versiyonla değiştir.
    Bu sayede test kodundaki `DatabaseManager(path)` çağrıları da %s placeholder'larını anlar.
    """
    monkeypatch.setattr(DatabaseManager, "_connect", _PGCompatDatabaseManager._connect)


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

_PG_TRUNCATE_TABLES = [
    "blocked_ips", "fp_rules", "asset_baselines", "attack_chain_state",
    "incident_events", "incidents", "topology_edges", "topology_nodes",
    "token_blacklist", "threat_intel_cache", "audit_log", "api_keys",
    "service_checks", "snmp_poll_history", "snmp_devices", "devices",
    "correlated_events", "normalized_logs", "raw_logs",
    "security_events", "alerts", "db_users", "sites", "tenants",
]


@pytest.fixture()
def mem_db():
    """normalized_logs tablosu olan izole in-memory SQLite — _PGCompatConn sarılı.
    sigma_executor'ın %s placeholder'larını ve date_trunc/to_char'ı destekler."""
    raw = sqlite3.connect(":memory:")
    raw.row_factory = sqlite3.Row
    raw.create_function("date_trunc", 2, _sqlite_date_trunc)
    raw.create_function("to_char", 2, _sqlite_to_char)
    raw.execute("""
        CREATE TABLE normalized_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id TEXT,
            event_action TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            timestamp TEXT,
            message TEXT,
            severity TEXT DEFAULT 'info',
            tenant_id TEXT DEFAULT 'default'
        )
    """)
    raw.commit()
    return _PGCompatConn(raw)


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
    test_db = _PGCompatDatabaseManager(db_path=db_file)
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
    monkeypatch.setattr("server.routes.network_intel.db", test_db)
    monkeypatch.setattr("server.routes.active_response.db", test_db)
    monkeypatch.setattr("server.routes.mitre.db", test_db)
    monkeypatch.setattr("server.routes.analytics.db", test_db)
    monkeypatch.setattr("server.log_store._db", test_db)

    tables = ", ".join(_PG_TRUNCATE_TABLES)
    with test_db._connect() as conn:
        conn.execute(f"TRUNCATE {tables} RESTART IDENTITY CASCADE")
        conn.execute("INSERT INTO tenants (id, name) VALUES ('default', 'Default') ON CONFLICT DO NOTHING")

    yield test_db
    test_db._pool.close()
