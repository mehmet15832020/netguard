"""
Pytest paylaşımlı fixture'ları.

session scope → tüm test süresince bir kez çalışır.
Token direkt oluşturulur — rate limited /auth/login endpoint'i çağrılmaz.
"""

import pytest
from server.auth import create_access_token


@pytest.fixture(scope="session")
def admin_token() -> str:
    """Admin JWT token'ını direkt oluştur (rate limit'i tetiklemez)."""
    return create_access_token(username="admin", role="admin")
