"""
NetGuard — Merkezi rate limiter

Tüm route'lar bu modülden import eder; ayrı instance yaratmaz.
Storage: RATELIMIT_STORAGE_URI env ile Redis'e geçilebilir (çok-worker prod için).
"""

import os

from fastapi import Request
from jose.jwt import get_unverified_claims
from slowapi import Limiter
from slowapi.util import get_remote_address

_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")


def _auth_key(request: Request) -> str:
    """Kimliği doğrulanmış endpoint'ler için JWT'den username, yoksa IP."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        try:
            payload = get_unverified_claims(auth[7:])
            sub = payload.get("sub")
            if sub:
                return f"user:{sub}"
        except Exception:
            pass
    return get_remote_address(request)


limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=_STORAGE_URI,
    headers_enabled=True,
    key_style="endpoint",
)
