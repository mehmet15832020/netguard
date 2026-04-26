"""
NetGuard — Auth endpoint'leri

POST /api/v1/auth/login        → JWT token al
POST /api/v1/auth/refresh      → Yeni access token al (refresh token ile)
POST /api/v1/auth/logout       → Token blacklist'e ekle (çıkış)
POST /api/v1/auth/agent-key    → Agent API key al (admin only)
GET  /api/v1/auth/me           → Mevcut kullanıcı bilgisi
"""

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from server.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ALGORITHM,
    SECRET_KEY,
    LoginRequest,
    Token,
    authenticate_user,
    create_access_token,
    create_refresh_token,
    get_current_user,
    register_agent_key,
    require_admin,
    verify_token,
    bearer_scheme,
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

    access  = create_access_token(user.username, user.role, user.tenant_id)
    refresh = create_refresh_token(user.username, user.role, user.tenant_id)
    logger.info(f"Giriş başarılı: {user.username} ({user.role})")

    return Token(
        access_token=access,
        refresh_token=refresh,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/auth/me", response_model=User)
def get_me(current_user: User = Depends(get_current_user)):
    """Mevcut kullanıcı bilgisini döndür."""
    return current_user


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/auth/refresh", response_model=Token)
@limiter.limit("10/minute")
def refresh(request: Request, body: RefreshRequest):
    """Geçerli bir refresh token ile yeni access + refresh token çifti al."""
    payload = verify_token(body.refresh_token, token_type="refresh")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz veya süresi dolmuş refresh token",
        )
    username  = payload["sub"]
    role      = payload["role"]
    tenant_id = payload.get("tid", "default")
    access      = create_access_token(username, role, tenant_id)
    refresh_new = create_refresh_token(username, role, tenant_id)
    return Token(
        access_token=access,
        refresh_token=refresh_new,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/auth/logout", status_code=200)
def logout(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    current_user: User = Depends(get_current_user),
):
    """Access token'ı blacklist'e ekle — anında geçersiz kılar."""
    from server.database import db
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        exp = payload.get("exp")
        if jti and exp:
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
            db.blacklist_token(jti, expires_at)
    except JWTError:
        pass
    return {"ok": True, "message": f"{current_user.username} oturumu kapatıldı"}


@router.post("/auth/agent-key")
def create_agent_key(
    request: Request,
    agent_id: str,
    admin: User = Depends(require_admin),
):
    """Agent için API key oluştur. Sadece admin kullanabilir. Key yalnızca bir kez gösterilir."""
    from server.database import db
    api_key = register_agent_key(agent_id)
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"'{agent_id}' için API key zaten mevcut. Sıfırlamak için önce silin.",
        )
    db.save_audit_event(
        actor=admin.username, action="api_key.create", resource=agent_id,
        ip_address=request.client.host if request.client else "",
    )
    return {
        "agent_id": agent_id,
        "api_key": api_key,
        "message": "Bu key'i güvenli saklayın, bir daha gösterilmeyecek.",
    }


@router.delete("/auth/agent-key/{agent_id}")
def delete_agent_key(
    request: Request,
    agent_id: str,
    admin: User = Depends(require_admin),
):
    """Agent API key'ini sil (sıfırlamak için önce sil, sonra yeniden oluştur)."""
    from server.database import db
    if db.get_api_key(agent_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key bulunamadı")
    db.delete_api_key(agent_id)
    db.save_audit_event(
        actor=admin.username, action="api_key.delete", resource=agent_id,
        ip_address=request.client.host if request.client else "",
    )
    return {"ok": True, "agent_id": agent_id}