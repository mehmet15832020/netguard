"""
NetGuard — Multi-tenant yönetimi

Tenant hiyerarşisi:  Tenant → Site → Device
Rol hiyerarşisi:     superadmin → admin → viewer

GET    /api/v1/tenants                        → Tüm tenant'ları listele (superadmin: hepsi, admin: sadece kendi)
POST   /api/v1/tenants                        → Yeni tenant oluştur (superadmin)
GET    /api/v1/tenants/{id}                   → Tenant detayı
PATCH  /api/v1/tenants/{id}                   → Tenant güncelle (superadmin)
DELETE /api/v1/tenants/{id}                   → Tenant sil (superadmin, default silinemez)

GET    /api/v1/tenants/{id}/sites             → Site listesi
POST   /api/v1/tenants/{id}/sites             → Yeni site oluştur (admin+)
DELETE /api/v1/tenants/{id}/sites/{site_id}   → Site sil (admin+)

GET    /api/v1/tenants/{id}/users             → Kullanıcı listesi
POST   /api/v1/tenants/{id}/users             → Yeni kullanıcı oluştur (admin+)
DELETE /api/v1/tenants/{id}/users/{username}  → Kullanıcı sil (admin+)
PATCH  /api/v1/tenants/{id}/users/{username}  → Şifre / rol güncelle (admin+)
"""

import re
import bcrypt
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from server.auth import User, get_current_user, require_admin, require_superadmin, tenant_scope
from server.database import db

router = APIRouter()

_SLUG_RE = re.compile(r'^[a-z0-9][a-z0-9\-]{0,62}$')


def _validate_slug(value: str, field: str) -> str:
    if not _SLUG_RE.match(value):
        raise HTTPException(
            status_code=400,
            detail=f"{field} sadece küçük harf, rakam ve tire içerebilir (örn: acme-corp)",
        )
    return value


def _check_tenant_access(tenant_id: str, current_user: User) -> None:
    """Admin kendi tenant'ına erişebilir; superadmin hepsine."""
    if current_user.role == "superadmin":
        return
    if current_user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Bu tenant'a erişim yetkiniz yok")


# ── Request modelleri ──────────────────────────────────────────────

class CreateTenantRequest(BaseModel):
    id: str
    name: str

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not _SLUG_RE.match(v):
            raise ValueError("id sadece küçük harf, rakam ve tire içerebilir")
        return v


class UpdateTenantRequest(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None


class CreateSiteRequest(BaseModel):
    id: str
    name: str
    location: str = ""
    tz: str = "UTC"

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not _SLUG_RE.match(v):
            raise ValueError("id sadece küçük harf, rakam ve tire içerebilir")
        return v


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "viewer"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in ("admin", "viewer"):
            raise ValueError("role: admin veya viewer olmalı")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Şifre en az 8 karakter olmalı")
        return v


class UpdateUserRequest(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ("admin", "viewer"):
            raise ValueError("role: admin veya viewer olmalı")
        return v


# ── Tenant endpoint'leri ──────────────────────────────────────────

@router.get("/tenants")
def list_tenants(current_user: User = Depends(get_current_user)):
    """Superadmin tüm tenant'ları, admin sadece kendi tenant'ını görür."""
    if current_user.role == "superadmin":
        return {"tenants": db.get_tenants()}
    tenant = db.get_tenant(current_user.tenant_id or "default")
    return {"tenants": [tenant] if tenant else []}


@router.post("/tenants", status_code=201)
def create_tenant(
    req: CreateTenantRequest,
    _: User = Depends(require_superadmin),
):
    """Yeni tenant oluştur. Sadece superadmin."""
    if not db.create_tenant(req.id, req.name):
        raise HTTPException(status_code=409, detail=f"'{req.id}' tenant ID zaten mevcut")
    # Default site otomatik oluştur
    db.create_site(f"{req.id}-main", req.id, "Ana Site")
    return {"ok": True, "tenant": db.get_tenant(req.id)}


@router.get("/tenants/{tenant_id}")
def get_tenant(tenant_id: str, current_user: User = Depends(get_current_user)):
    _check_tenant_access(tenant_id, current_user)
    tenant = db.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant bulunamadı")
    return tenant


@router.patch("/tenants/{tenant_id}")
def update_tenant(
    tenant_id: str,
    req: UpdateTenantRequest,
    _: User = Depends(require_superadmin),
):
    updated = db.update_tenant(
        tenant_id,
        name=req.name,
        is_active=(int(req.is_active) if req.is_active is not None else None),
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Tenant bulunamadı")
    return {"ok": True, "tenant": db.get_tenant(tenant_id)}


@router.delete("/tenants/{tenant_id}", status_code=200)
def delete_tenant(tenant_id: str, _: User = Depends(require_superadmin)):
    if tenant_id == "default":
        raise HTTPException(status_code=400, detail="Default tenant silinemez")
    if not db.delete_tenant(tenant_id):
        raise HTTPException(status_code=404, detail="Tenant bulunamadı")
    return {"ok": True}


# ── Site endpoint'leri ────────────────────────────────────────────

@router.get("/tenants/{tenant_id}/sites")
def list_sites(tenant_id: str, current_user: User = Depends(get_current_user)):
    _check_tenant_access(tenant_id, current_user)
    if not db.get_tenant(tenant_id):
        raise HTTPException(status_code=404, detail="Tenant bulunamadı")
    return {"sites": db.get_sites(tenant_id)}


@router.post("/tenants/{tenant_id}/sites", status_code=201)
def create_site(
    tenant_id: str,
    req: CreateSiteRequest,
    current_user: User = Depends(require_admin),
):
    _check_tenant_access(tenant_id, current_user)
    if not db.get_tenant(tenant_id):
        raise HTTPException(status_code=404, detail="Tenant bulunamadı")
    if not db.create_site(req.id, tenant_id, req.name, req.location, req.tz):
        raise HTTPException(status_code=409, detail=f"'{req.id}' site ID zaten mevcut")
    return {"ok": True, "site": db.get_site(req.id)}


@router.delete("/tenants/{tenant_id}/sites/{site_id}")
def delete_site(
    tenant_id: str,
    site_id: str,
    current_user: User = Depends(require_admin),
):
    _check_tenant_access(tenant_id, current_user)
    site = db.get_site(site_id)
    if not site or site["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="Site bulunamadı")
    db.delete_site(site_id)
    return {"ok": True}


# ── Kullanıcı endpoint'leri ──────────────────────────────────────

@router.get("/tenants/{tenant_id}/users")
def list_users(tenant_id: str, current_user: User = Depends(require_admin)):
    _check_tenant_access(tenant_id, current_user)
    if not db.get_tenant(tenant_id):
        raise HTTPException(status_code=404, detail="Tenant bulunamadı")
    return {"users": db.get_db_users(tenant_id)}


@router.post("/tenants/{tenant_id}/users", status_code=201)
def create_user(
    tenant_id: str,
    req: CreateUserRequest,
    current_user: User = Depends(require_admin),
):
    _check_tenant_access(tenant_id, current_user)
    if not db.get_tenant(tenant_id):
        raise HTTPException(status_code=404, detail="Tenant bulunamadı")
    hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    if not db.create_db_user(req.username, hashed, req.role, tenant_id):
        raise HTTPException(status_code=409, detail=f"'{req.username}' kullanıcı adı zaten mevcut")
    return {"ok": True, "username": req.username, "role": req.role, "tenant_id": tenant_id}


@router.patch("/tenants/{tenant_id}/users/{username}")
def update_user(
    tenant_id: str,
    username: str,
    req: UpdateUserRequest,
    current_user: User = Depends(require_admin),
):
    _check_tenant_access(tenant_id, current_user)
    user_row = db.get_db_user(username)
    if not user_row or user_row["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    if req.password:
        hashed = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
        db.update_db_user_password(username, hashed)
    if req.role:
        db.update_db_user_role(username, req.role)
    return {"ok": True}


@router.delete("/tenants/{tenant_id}/users/{username}")
def delete_user(
    tenant_id: str,
    username: str,
    current_user: User = Depends(require_admin),
):
    _check_tenant_access(tenant_id, current_user)
    user_row = db.get_db_user(username)
    if not user_row or user_row["tenant_id"] != tenant_id:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    db.delete_db_user(username)
    return {"ok": True}
