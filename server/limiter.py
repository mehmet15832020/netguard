"""
NetGuard — Merkezi rate limiter

Tüm route'lar bu modülden import eder; ayrı instance yaratmaz.
Storage: RATELIMIT_STORAGE_URI env ile Redis'e geçilebilir (çok-worker prod için).
"""

import logging
import os

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")

if _STORAGE_URI == "memory://" and os.getenv("WEB_CONCURRENCY", "1") != "1":
    logger.warning(
        "Rate limiter memory:// storage is not shared across workers. "
        "Set RATELIMIT_STORAGE_URI=redis://... for multi-worker deployments."
    )


def _auth_key(request: Request) -> str:
    """Kimliği doğrulanmış endpoint'ler için doğrulanmış JWT'den username, yoksa IP."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:]
        try:
            from server.auth import verify_token
            payload = verify_token(token, token_type="access")
            sub = payload.get("sub")
            if sub:
                return f"user:{sub}"
        except Exception as exc:
            logger.debug("JWT doğrulaması başarısız, IP'ye dönülüyor: %s", exc)
    return get_remote_address(request)


limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=_STORAGE_URI,
    headers_enabled=True,
    key_style="endpoint",
)
