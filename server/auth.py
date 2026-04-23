"""
NetGuard — Authentication

JWT tabanlı kullanıcı kimlik doğrulama.
Agent'lar için API key sistemi.

Gerçek üretim ortamında kullanıcılar veritabanında saklanır.
Şu an basit in-memory yapı kullanıyoruz.
"""

import hashlib
import os
import secrets
import logging
import bcrypt
from datetime import datetime, timedelta, timezone
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from jose import JWTError, jwt
from pydantic import BaseModel

load_dotenv()

logger = logging.getLogger(__name__)

# JWT ayarları
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY .env dosyasında tanımlı değil. "
        "Örnek: JWT_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    )
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES  = int(os.getenv("JWT_EXPIRE_MINUTES",         "60"))
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_REFRESH_EXPIRE_MINUTES", str(60 * 24 * 7)))



# Security scheme'ler
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ─── Modeller ────────────────────────────────────────────────────

class User(BaseModel):
    username: str
    role: str = "viewer"    # admin veya viewer


class UserInDB(User):
    hashed_password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class LoginRequest(BaseModel):
    username: str
    password: str


# ─── Kullanıcı deposu (şimdilik in-memory) ───────────────────────

def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


# Varsayılan kullanıcılar — .env'den okunur, yoksa default
_USERS: dict[str, UserInDB] = {
    os.getenv("ADMIN_USERNAME", "admin"): UserInDB(
        username=os.getenv("ADMIN_USERNAME", "admin"),
        role="admin",
        hashed_password=_hash(os.getenv("ADMIN_PASSWORD", "netguard123")),
    ),
    os.getenv("VIEWER_USERNAME", "viewer"): UserInDB(
        username=os.getenv("VIEWER_USERNAME", "viewer"),
        role="viewer",
        hashed_password=_hash(os.getenv("VIEWER_PASSWORD", "viewer123")),
    ),
}

# ─── Agent API key yönetimi ──────────────────────────────────────

def generate_api_key() -> str:
    """Kriptografik olarak güvenli API key üretir."""
    return secrets.token_urlsafe(32)


def _hash_api_key(key: str) -> str:
    """API key'in SHA-256 hash'ini döndür."""
    return hashlib.sha256(key.encode()).hexdigest()


def register_agent_key(agent_id: str) -> Optional[str]:
    """Agent için API key oluştur; zaten varsa None döndür (key tekrar gösterilmez)."""
    from server.database import db
    if db.get_api_key(agent_id) is not None:
        return None
    new_key = generate_api_key()
    db.save_api_key(agent_id, _hash_api_key(new_key))
    logger.info(f"API key oluşturuldu: {agent_id}")
    return new_key


def verify_api_key(api_key: str) -> Optional[str]:
    """API key geçerliyse agent_id döndür, değilse None."""
    from server.database import db
    key_hash = _hash_api_key(api_key)
    for agent_id, stored_hash in db.get_all_api_keys().items():
        if secrets.compare_digest(stored_hash, key_hash):
            return agent_id
    return None


# ─── JWT işlemleri ───────────────────────────────────────────────

def create_access_token(username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": username, "role": role, "type": "access", "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM,
    )


def create_refresh_token(username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": username, "role": role, "type": "refresh", "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM,
    )


def verify_token(token: str, token_type: str = "access") -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != token_type:
            return None
        return payload
    except JWTError:
        return None


# ─── Kullanıcı doğrulama ─────────────────────────────────────────

def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    user = _USERS.get(username)
    if not user:
        return None
    if not bcrypt.checkpw(password.encode(), user.hashed_password.encode()):
        return None
    return user


# ─── FastAPI dependency'leri ─────────────────────────────────────

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> User:
    """
    JWT token doğrular. Geçersizse 401 döner.
    Korunan endpoint'lerde Depends(get_current_user) kullan.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kimlik doğrulama gerekli",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz veya süresi dolmuş token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return User(username=payload["sub"], role=payload["role"])


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Sadece admin rolüne izin verir."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bu işlem için admin yetkisi gerekli",
        )
    return current_user


def get_agent_from_api_key(
    api_key: Optional[str] = Security(api_key_header),
) -> str:
    """
    Agent endpoint'leri için API key doğrular.
    Geçersizse 401 döner.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header gerekli",
        )

    agent_id = verify_api_key(api_key)
    if not agent_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz API key",
        )
    return agent_id