import os
import secrets
from datetime import datetime, timedelta
from typing import Optional, Union

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.client import Client

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security schemes
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def generate_api_key() -> str:
    return f"c6_{secrets.token_urlsafe(32)}"


# --- JWT for client-based auth (legacy / programmatic) ---

def create_client_jwt_token(client_id: str, client_name: str) -> str:
    """Create a JWT token for client-based (API key) authentication."""
    payload = {
        "sub": client_id,
        "name": client_name,
        "type": "client",
        "iss": "aegis",
        "exp": datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.AEGIS_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


# --- JWT for user-based auth (RBAC) ---

def create_user_jwt_token(user_id: str, email: str, role: str, client_id: Optional[str]) -> str:
    """Create a JWT token for user-based (email/password) authentication."""
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "client_id": client_id,
        "type": "user",
        "iss": "aegis",
        "exp": datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.AEGIS_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.AEGIS_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require_iss": False},  # Don't reject legacy tokens without iss
        )
        # Validate issuer if present (new tokens always have it)
        if "iss" in payload and payload["iss"] != "aegis":
            raise HTTPException(status_code=401, detail="Invalid token issuer")
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# --- Unified auth context ---

class AuthContext:
    """Represents the authenticated entity -- either a User or an API-key Client."""

    def __init__(
        self,
        client: Client,
        user=None,
        role: str = "admin",
        user_id: Optional[str] = None,
        email: Optional[str] = None,
    ):
        self.client = client
        self.user = user
        self.role = role
        self.user_id = user_id
        self.email = email

    @property
    def client_id(self) -> str:
        return self.client.id

    @property
    def is_api_key(self) -> bool:
        return self.user is None


async def get_auth_context(
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> AuthContext:
    """
    Unified authentication dependency.
    Accepts either X-API-Key header (grants admin role) or Bearer JWT (user or client token).
    """
    # --- Try API key first ---
    if api_key:
        result = await db.execute(select(Client).where(Client.api_key == api_key))
        client = result.scalar_one_or_none()
        if client:
            return AuthContext(client=client, role="admin")

    # --- Try Bearer JWT ---
    if bearer:
        payload = decode_jwt_token(bearer.credentials)
        token_type = payload.get("type", "client")

        if token_type == "user":
            # User JWT -- import here to avoid circular imports
            from app.models.user import User

            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(status_code=401, detail="Invalid token payload")

            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if not user or not user.is_active:
                raise HTTPException(status_code=401, detail="User not found or inactive")

            # Resolve client
            client = None
            if user.client_id:
                result = await db.execute(select(Client).where(Client.id == user.client_id))
                client = result.scalar_one_or_none()

            if not client:
                # Fallback: get the first client (demo)
                result = await db.execute(select(Client).limit(1))
                client = result.scalar_one_or_none()

            if not client:
                raise HTTPException(status_code=500, detail="No client configured")

            return AuthContext(
                client=client,
                user=user,
                role=user.role.value if hasattr(user.role, "value") else user.role,
                user_id=user.id,
                email=user.email,
            )

        else:
            # Legacy client JWT
            client_id = payload.get("sub")
            if client_id:
                result = await db.execute(select(Client).where(Client.id == client_id))
                client = result.scalar_one_or_none()
                if client:
                    return AuthContext(client=client, role="admin")

    raise HTTPException(status_code=401, detail="Invalid authentication credentials")


# --- Backward-compatible dependency ---

async def get_current_client(
    auth: AuthContext = Depends(get_auth_context),
) -> Client:
    """Backward-compatible: returns the Client object from auth context."""
    return auth.client


# --- Role-checking dependencies ---

async def require_admin(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    """Only admin role (or API key, which is implicitly admin)."""
    if auth.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required",
        )
    return auth


async def require_analyst(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    """Admin or analyst role."""
    if auth.role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=403,
            detail="Analyst or admin access required",
        )
    return auth


async def require_viewer(
    auth: AuthContext = Depends(get_auth_context),
) -> AuthContext:
    """Any authenticated user (admin, analyst, or viewer)."""
    # If we got here, the user is already authenticated
    return auth


# --- Seed functions ---

async def seed_demo_client(db: AsyncSession) -> Client:
    """Create a demo client if none exist."""
    result = await db.execute(select(Client).where(Client.slug == "demo"))
    existing = result.scalar_one_or_none()
    if existing:
        return existing

    demo_client = Client(
        name="AEGIS Demo",
        slug="demo",
        api_key=generate_api_key(),
        settings={
            "scan_interval": 3600,
            "auto_response": True,
            "notification_channels": ["webhook"],
            "notify_on_critical": True,
            "notify_on_high": True,
            "notify_on_actions": True,
            "email_enabled": False,
            "email_recipients": [],
        },
        guardrails={
            "block_ip": "auto_approve",
            "isolate_host": "require_approval",
            "revoke_creds": "require_approval",
            "shutdown_service": "never_auto",
            "firewall_rule": "auto_approve",
            "quarantine_file": "auto_approve",
        },
    )
    db.add(demo_client)
    await db.commit()
    await db.refresh(demo_client)
    return demo_client


async def seed_default_admin(db: AsyncSession, client: Client) -> None:
    """Create default admin user if no users exist."""
    from app.models.user import User, UserRole

    result = await db.execute(select(User).limit(1))
    existing = result.scalar_one_or_none()
    if existing:
        return

    admin_user = User(
        email="admin@aegis.local",
        password_hash=hash_password(os.environ.get("AEGIS_ADMIN_PASSWORD", "changeme-on-first-login")),
        name="Admin",
        role=UserRole.admin,
        client_id=client.id,
        is_active=True,
    )
    db.add(admin_user)
    await db.commit()
