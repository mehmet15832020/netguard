"""
Pytest paylaşımlı fixture'ları.

session scope → tüm test süresince bir kez çalışır.
Token direkt oluşturulur — rate limited /auth/login endpoint'i çağrılmaz.
"""

import pytest
from server.auth import create_access_token
from server.database import DatabaseManager


@pytest.fixture(scope="session")
def admin_token() -> str:
    """Admin JWT token'ını direkt oluştur (rate limit'i tetiklemez)."""
    return create_access_token(username="admin", role="admin")


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
    return test_db
