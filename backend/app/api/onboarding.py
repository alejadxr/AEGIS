"""
Self-serve onboarding / signup endpoint.

POST /api/v1/onboarding/signup  (no auth required)
"""

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import get_db
from app.core.auth import generate_api_key, hash_password, create_user_jwt_token
from app.core.audit import log_audit
from app.models.client import Client
from app.models.user import User, UserRole

limiter = Limiter(key_func=get_remote_address)

router = APIRouter(prefix="/onboarding", tags=["onboarding"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SignupRequest(BaseModel):
    org_name: str = Field(..., min_length=1, max_length=200, pattern=r"^[\w\s\-\.&,]+$")
    admin_name: str = Field(..., min_length=1, max_length=100)
    admin_email: EmailStr
    admin_password: str = Field(..., min_length=6, max_length=128)

    @field_validator("org_name")
    @classmethod
    def org_name_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Organization name is required")
        return v


class SignupResponse(BaseModel):
    token: str
    client_id: str
    client_name: str
    api_key: str
    user: dict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _make_slug(name: str) -> str:
    slug = _SLUG_RE.sub("-", name.lower()).strip("-")
    return slug or "org"


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/signup", response_model=SignupResponse)
@limiter.limit("5/minute")
async def signup(request: Request, body: SignupRequest, db: AsyncSession = Depends(get_db)):
    """Create a new organization (Client) + admin User. Returns JWT."""

    email_lower = body.admin_email.lower()

    # -- Uniqueness checks --
    existing_email = await db.execute(
        select(func.count()).select_from(User).where(User.email == email_lower)
    )
    if existing_email.scalar_one() > 0:
        raise HTTPException(status_code=409, detail="Email already registered")

    slug = _make_slug(body.org_name)
    existing_slug = await db.execute(
        select(func.count()).select_from(Client).where(Client.slug == slug)
    )
    if existing_slug.scalar_one() > 0:
        raise HTTPException(status_code=409, detail="Organization name already taken")

    # -- Create Client --
    client = Client(
        name=body.org_name.strip(),
        slug=slug,
        api_key=generate_api_key(),
        tier="free",
        max_nodes=3,
        max_assets=25,
        max_users=3,
        settings={
            "scan_interval": 3600,
            "auto_response": True,
            "notification_channels": ["webhook"],
            "notify_on_critical": True,
            "notify_on_high": True,
            "notify_on_actions": True,
            "intel_sharing_enabled": False,
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
    db.add(client)
    await db.flush()  # get client.id

    # -- Create admin User --
    user = User(
        email=email_lower,
        password_hash=hash_password(body.admin_password),
        name=body.admin_name.strip(),
        role=UserRole.admin,
        client_id=client.id,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(client)
    await db.refresh(user)

    # -- Audit --
    await log_audit(
        db, "signup",
        f"New org '{client.name}' created by {user.email}",
        client_id=client.id,
        user_id=user.id,
    )
    await db.commit()

    # -- JWT --
    token = create_user_jwt_token(
        user_id=user.id,
        email=user.email,
        role=user.role.value,
        client_id=client.id,
    )

    return SignupResponse(
        token=token,
        client_id=client.id,
        client_name=client.name,
        api_key=client.api_key,
        user={
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role.value,
        },
    )
