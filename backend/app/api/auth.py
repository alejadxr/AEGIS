from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import get_db
from app.core.auth import (
    AuthContext,
    create_client_jwt_token,
    create_user_jwt_token,
    generate_api_key,
    get_current_client,
    get_auth_context,
    hash_password,
    require_admin,
    require_viewer,
    verify_password,
)
from app.core.audit import log_audit
from app.models.client import Client
from app.models.user import User, UserRole

limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/auth", tags=["auth"])


# --- Schemas ---

class LoginRequest(BaseModel):
    api_key: str


class LoginResponse(BaseModel):
    token: str
    client_id: str
    client_name: str


class UserLoginRequest(BaseModel):
    email: str
    password: str


class UserLoginResponse(BaseModel):
    token: str
    user: "UserOut"


class UserRegisterRequest(BaseModel):
    email: str
    password: str
    name: str
    role: str = "viewer"
    client_id: Optional[str] = None


class UserOut(BaseModel):
    id: str
    email: str
    name: str
    role: str
    client_id: Optional[str] = None
    is_active: bool
    created_at: Optional[str] = None
    last_login: Optional[str] = None


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    client_id: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ApiKeyResponse(BaseModel):
    api_key: str
    client_id: str


class ClientInfo(BaseModel):
    id: str
    name: str
    slug: str
    settings: dict
    guardrails: dict


class MeResponse(BaseModel):
    # Returns user info if user auth, client info if API key auth
    auth_type: str  # "user" or "api_key"
    user: Optional[UserOut] = None
    client: ClientInfo


# --- Legacy client auth routes ---

@router.post("/login", response_model=LoginResponse)
async def login_api_key(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate with API key and get a JWT token (legacy client auth)."""
    result = await db.execute(select(Client).where(Client.api_key == body.api_key))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(status_code=401, detail="Invalid API key")

    token = create_client_jwt_token(client.id, client.name)
    return LoginResponse(token=token, client_id=client.id, client_name=client.name)


@router.post("/api-key", response_model=ApiKeyResponse)
async def regenerate_api_key(
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Regenerate API key for the current client. Admin only."""
    new_key = generate_api_key()
    auth.client.api_key = new_key
    await db.commit()
    return ApiKeyResponse(api_key=new_key, client_id=auth.client.id)


# --- User auth routes ---

@router.post("/user/login", response_model=UserLoginResponse)
@limiter.limit("10/minute")
async def login_user(request: Request, body: UserLoginRequest, db: AsyncSession = Depends(get_db)):
    """Login with email and password. Returns JWT token with user info."""
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    # Update last_login
    user.last_login = datetime.utcnow()

    # Audit log
    if user.client_id:
        await log_audit(
            db, "user_login",
            f"User {user.email} logged in",
            client_id=user.client_id,
            user_id=user.id,
        )

    await db.commit()

    role_value = user.role.value if hasattr(user.role, "value") else user.role
    token = create_user_jwt_token(user.id, user.email, role_value, user.client_id)

    return UserLoginResponse(
        token=token,
        user=UserOut(
            id=user.id,
            email=user.email,
            name=user.name,
            role=role_value,
            client_id=user.client_id,
            is_active=user.is_active,
            created_at=user.created_at.isoformat() if user.created_at else None,
            last_login=user.last_login.isoformat() if user.last_login else None,
        ),
    )


@router.post("/register", response_model=UserOut, status_code=201)
async def register_user(
    body: UserRegisterRequest,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Register a new user. Admin only."""
    # Validate role
    valid_roles = [r.value for r in UserRole]
    if body.role not in valid_roles:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role. Must be one of: {valid_roles}",
        )

    # Check email uniqueness
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    # Validate password length
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    # Force client_id to admin's own tenant -- never accept from body
    client_id = auth.client.id

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        name=body.name,
        role=UserRole(body.role),
        client_id=client_id,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    role_value = user.role.value if hasattr(user.role, "value") else user.role
    return UserOut(
        id=user.id,
        email=user.email,
        name=user.name,
        role=role_value,
        client_id=user.client_id,
        is_active=user.is_active,
        created_at=user.created_at.isoformat() if user.created_at else None,
        last_login=None,
    )


@router.get("/me", response_model=MeResponse)
async def get_me(auth: AuthContext = Depends(get_auth_context)):
    """Get current authenticated entity info (user or API key client)."""
    client_info = ClientInfo(
        id=auth.client.id,
        name=auth.client.name,
        slug=auth.client.slug,
        settings=auth.client.settings or {},
        guardrails=auth.client.guardrails or {},
    )

    user_out = None
    if auth.user:
        role_value = auth.user.role.value if hasattr(auth.user.role, "value") else auth.user.role
        user_out = UserOut(
            id=auth.user.id,
            email=auth.user.email,
            name=auth.user.name,
            role=role_value,
            client_id=auth.user.client_id,
            is_active=auth.user.is_active,
            created_at=auth.user.created_at.isoformat() if auth.user.created_at else None,
            last_login=auth.user.last_login.isoformat() if auth.user.last_login else None,
        )

    return MeResponse(
        auth_type="user" if auth.user else "api_key",
        user=user_out,
        client=client_info,
    )


@router.get("/users", response_model=list[UserOut])
async def list_users(
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all users for the current tenant. Admin only."""
    result = await db.execute(
        select(User)
        .where(User.client_id == auth.client.id)
        .order_by(User.created_at.desc())
    )
    users = result.scalars().all()

    return [
        UserOut(
            id=u.id,
            email=u.email,
            name=u.name,
            role=u.role.value if hasattr(u.role, "value") else u.role,
            client_id=u.client_id,
            is_active=u.is_active,
            created_at=u.created_at.isoformat() if u.created_at else None,
            last_login=u.last_login.isoformat() if u.last_login else None,
        )
        for u in users
    ]


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: str,
    body: UserUpdate,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update user role, status, or info. Admin only. Scoped to own tenant."""
    result = await db.execute(
        select(User).where(User.id == user_id, User.client_id == auth.client.id)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if body.name is not None:
        user.name = body.name
    if body.role is not None:
        valid_roles = [r.value for r in UserRole]
        if body.role not in valid_roles:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid role. Must be one of: {valid_roles}",
            )
        user.role = UserRole(body.role)
    if body.is_active is not None:
        user.is_active = body.is_active
    # Ignore client_id changes -- users stay in their tenant

    await db.commit()
    await db.refresh(user)

    role_value = user.role.value if hasattr(user.role, "value") else user.role
    return UserOut(
        id=user.id,
        email=user.email,
        name=user.name,
        role=role_value,
        client_id=user.client_id,
        is_active=user.is_active,
        created_at=user.created_at.isoformat() if user.created_at else None,
        last_login=user.last_login.isoformat() if user.last_login else None,
    )


@router.delete("/users/{user_id}", status_code=204)
async def deactivate_user(
    user_id: str,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate a user (soft delete). Admin only. Scoped to own tenant."""
    result = await db.execute(
        select(User).where(User.id == user_id, User.client_id == auth.client.id)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent self-deactivation
    if auth.user_id and auth.user_id == user_id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    user.is_active = False
    await db.commit()


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Change own password. Requires current password verification."""
    if not auth.user:
        raise HTTPException(
            status_code=400,
            detail="Password change only available for user accounts, not API key auth",
        )

    if not verify_password(body.current_password, auth.user.password_hash):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")

    auth.user.password_hash = hash_password(body.new_password)
    await db.commit()

    return {"message": "Password changed successfully"}
