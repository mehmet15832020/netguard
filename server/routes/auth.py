"""
NetGuard — Auth endpoint'leri

POST /api/v1/auth/login        → JWT token al
POST /api/v1/auth/agent-key    → Agent API key al (admin only)
GET  /api/v1/auth/me           → Mevcut kullanıcı bilgisi
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from server.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    LoginRequest,
    Token,
    authenticate_user,
    create_access_token,
    get_current_user,
    register_agent_key,
    require_admin,
    User,
)

logger = logging.getLogger(__name__)
router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post("/auth/login", response_model=Token)
@limiter.limit("5/minute")
def login(request: Request, body: LoginRequest):
    """Kullanıcı adı ve şifre ile JWT token al."""
    user = authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kullanıcı adı veya şifre hatalı",
        )

    token = create_access_token(user.username, user.role)
    logger.info(f"Giriş başarılı: {user.username} ({user.role})")

    return Token(
        access_token=token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/auth/me", response_model=User)
def get_me(current_user: User = Depends(get_current_user)):
    """Mevcut kullanıcı bilgisini döndür."""
    return current_user


@router.post("/auth/agent-key")
def create_agent_key(
    agent_id: str,
    _: User = Depends(require_admin),
):
    """Agent için API key oluştur. Sadece admin kullanabilir."""
    api_key = register_agent_key(agent_id)
    return {
        "agent_id": agent_id,
        "api_key": api_key,
        "message": "Bu key'i güvenli saklayın, bir daha gösterilmeyecek.",
    }