"""
NetGuard — Auth endpoint'leri

POST /api/v1/auth/login          → JWT token al (TOTP etkinse mfa_required=true)
POST /api/v1/auth/refresh        → Yeni access token al (refresh token ile)
POST /api/v1/auth/logout         → Token blacklist'e ekle (çıkış)
POST /api/v1/auth/agent-key      → Agent API key + mTLS client sertifikası al (admin only)
DELETE /api/v1/auth/agent-key/{agent_id} → API key + tüm sertifikaları sil/iptal et
POST /api/v1/auth/agent-key/{agent_id}/revoke-cert → Sadece sertifikaları iptal et (key kalır)
GET  /api/v1/auth/me             → Mevcut kullanıcı bilgisi
POST /api/v1/auth/totp-setup     → TOTP secret üret, otpauth URI döner
POST /api/v1/auth/totp-confirm   → TOTP kodunu doğrula ve etkinleştir
POST /api/v1/auth/totp-verify    → MFA pending token + kod → tam token
POST /api/v1/auth/totp-disable   → TOTP'u devre dışı bırak
"""

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError
from pydantic import BaseModel
import pyotp
from server.limiter import limiter
from server.agent_pki import issue_agent_certificate
from server.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ALGORITHM,
    SECRET_KEY,
    LoginRequest,
    Token,
    authenticate_user,
    create_access_token,
    create_mfa_token,
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


@router.post("/auth/login", response_model=Token)
@limiter.limit("5/minute")
def login(request: Request, response: Response, body: LoginRequest):
    from server.database import db
    user = authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kullanıcı adı veya şifre hatalı",
        )

    user_totp = db.get_user_totp(user.username)
    if user_totp["totp_enabled"]:
        mfa_token = create_mfa_token(user.username, user.role, user.tenant_id)
        logger.info("MFA gerekli: %s", user.username)
        return Token(mfa_required=True, mfa_token=mfa_token)

    access  = create_access_token(user.username, user.role, user.tenant_id)
    refresh = create_refresh_token(user.username, user.role, user.tenant_id)
    logger.info("Giriş başarılı: %s (%s)", user.username, user.role)
    return Token(
        access_token=access,
        refresh_token=refresh,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/auth/me", response_model=User)
def get_me(current_user: User = Depends(get_current_user)):
    from server.database import db
    totp_data = db.get_user_totp(current_user.username)
    return User(
        username=current_user.username,
        role=current_user.role,
        tenant_id=current_user.tenant_id,
        totp_enabled=totp_data["totp_enabled"],
    )


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/auth/refresh", response_model=Token)
@limiter.limit("10/minute")
def refresh(request: Request, response: Response, body: RefreshRequest):
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

    cert_pem, key_pem, serial_decimal, fingerprint, expires_at = issue_agent_certificate(agent_id)
    db.save_agent_certificate(agent_id, serial_decimal, fingerprint, expires_at)
    db.save_audit_event(
        actor=admin.username, action="agent_cert.issue", resource=agent_id,
        ip_address=request.client.host if request.client else "",
    )

    return {
        "agent_id": agent_id,
        "api_key": api_key,
        "client_cert_pem": cert_pem.decode(),
        "client_key_pem": key_pem.decode(),
        "cert_expires_at": expires_at.isoformat(),
        "message": (
            "Bu key ve sertifikayı güvenli saklayın, bir daha gösterilmeyecek. "
            "Sertifika NETGUARD_CLIENT_CERT/NETGUARD_CLIENT_KEY ile agent'a tanımlanmalı."
        ),
    }


@router.delete("/auth/agent-key/{agent_id}")
def delete_agent_key(
    request: Request,
    agent_id: str,
    admin: User = Depends(require_admin),
):
    from server.database import db
    if db.get_api_key(agent_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key bulunamadı")
    db.delete_api_key(agent_id)
    revoked = db.revoke_all_agent_certificates(agent_id)
    db.save_audit_event(
        actor=admin.username, action="api_key.delete", resource=agent_id,
        ip_address=request.client.host if request.client else "",
    )
    return {"ok": True, "agent_id": agent_id, "certificates_revoked": revoked}


@router.post("/auth/agent-key/{agent_id}/revoke-cert")
def revoke_agent_certificates(
    request: Request,
    agent_id: str,
    admin: User = Depends(require_admin),
):
    """API key'i silmeden sadece mTLS sertifikalarını iptal eder (kayıp/sızıntı senaryosu)."""
    from server.database import db
    revoked = db.revoke_all_agent_certificates(agent_id)
    db.save_audit_event(
        actor=admin.username, action="agent_cert.revoke", resource=agent_id,
        ip_address=request.client.host if request.client else "",
    )
    return {"ok": True, "agent_id": agent_id, "certificates_revoked": revoked}


# ─── TOTP endpoint'leri ──────────────────────────────────────────


class TotpConfirmRequest(BaseModel):
    code: str


class TotpVerifyRequest(BaseModel):
    mfa_token: str
    code: str


@router.post("/auth/totp-setup")
@limiter.limit("5/minute")
def totp_setup(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
):
    from server.database import db
    secret = pyotp.random_base32()
    db.set_user_totp_secret(
        current_user.username, secret,
        current_user.role, current_user.tenant_id or "default",
    )
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(
        name=current_user.username,
        issuer_name="NetGuard",
    )
    db.save_audit_event(
        actor=current_user.username, action="totp.setup", resource=current_user.username,
        ip_address=request.client.host if request.client else "",
    )
    return {"secret": secret, "otpauth_uri": uri}


@router.post("/auth/totp-confirm")
@limiter.limit("5/minute")
def totp_confirm(
    request: Request,
    response: Response,
    body: TotpConfirmRequest,
    current_user: User = Depends(get_current_user),
):
    from server.database import db
    user_totp = db.get_user_totp(current_user.username)
    if not user_totp["totp_secret"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Önce TOTP kurulumu yapınız (/auth/totp-setup)",
        )
    totp = pyotp.TOTP(user_totp["totp_secret"])
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Geçersiz TOTP kodu",
        )
    db.enable_user_totp(current_user.username)
    db.save_audit_event(
        actor=current_user.username, action="totp.enabled", resource=current_user.username,
        ip_address=request.client.host if request.client else "",
    )
    return {"ok": True, "message": "TOTP başarıyla etkinleştirildi"}


@router.post("/auth/totp-verify", response_model=Token)
@limiter.limit("5/minute")
def totp_verify(request: Request, response: Response, body: TotpVerifyRequest):
    from server.database import db
    payload = verify_token(body.mfa_token, token_type="mfa_pending")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz veya süresi dolmuş MFA token",
        )
    username  = payload["sub"]
    role      = payload["role"]
    tenant_id = payload.get("tid", "default")

    user_totp = db.get_user_totp(username)
    if not user_totp["totp_secret"] or not user_totp["totp_enabled"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bu kullanıcı için TOTP etkin değil",
        )
    totp = pyotp.TOTP(user_totp["totp_secret"])
    if not totp.verify(body.code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz TOTP kodu",
        )
    access      = create_access_token(username, role, tenant_id)
    refresh_new = create_refresh_token(username, role, tenant_id)
    logger.info("MFA doğrulama başarılı: %s", username)
    return Token(
        access_token=access,
        refresh_token=refresh_new,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/auth/totp-disable")
@limiter.limit("5/minute")
def totp_disable(
    request: Request,
    response: Response,
    target_username: str = "",
    current_user: User = Depends(get_current_user),
):
    from server.database import db
    subject = target_username if target_username else current_user.username
    if subject != current_user.username and current_user.role not in ("admin", "superadmin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Başka kullanıcının TOTP'unu kapatmak için admin yetkisi gerekli",
        )
    db.disable_user_totp(subject)
    db.save_audit_event(
        actor=current_user.username, action="totp.disabled", resource=subject,
        ip_address=request.client.host if request.client else "",
    )
    return {"ok": True, "message": f"{subject} için TOTP devre dışı bırakıldı"}
