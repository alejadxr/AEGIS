"""PayPal payment processing for AEGIS tier upgrades."""

import httpx
import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.core.auth import AuthContext, require_viewer
from app.services.subscription import TIERS

logger = logging.getLogger("aegis.payments")
router = APIRouter(prefix="/payments", tags=["payments"])

TIER_PRICES = {
    "pro": {
        "price": "29.00",
        "name": "AEGIS Pro",
        "description": "Pro tier - 25 nodes, 500 assets",
    },
    "enterprise": {
        "price": "99.00",
        "name": "AEGIS Enterprise",
        "description": "Enterprise - unlimited nodes, assets, users",
    },
}


async def get_paypal_token() -> str:
    """Obtain a PayPal OAuth2 access token."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{settings.PAYPAL_API_URL}/v1/oauth2/token",
            data="grant_type=client_credentials",
            auth=(settings.PAYPAL_CLIENT_ID, settings.PAYPAL_SECRET),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        return resp.json()["access_token"]


class CreateOrderRequest(BaseModel):
    tier: str  # "pro" or "enterprise"


class CaptureOrderRequest(BaseModel):
    order_id: str


@router.post("/create-order")
async def create_order(
    body: CreateOrderRequest,
    auth: AuthContext = Depends(require_viewer),
):
    """Create a PayPal checkout order for a tier upgrade."""
    if body.tier not in TIER_PRICES:
        raise HTTPException(400, f"Invalid tier: {body.tier}")
    if not settings.PAYPAL_CLIENT_ID or not settings.PAYPAL_SECRET:
        raise HTTPException(503, "Payment system not configured")

    pricing = TIER_PRICES[body.tier]
    token = await get_paypal_token()

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{settings.PAYPAL_API_URL}/v2/checkout/orders",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={
                "intent": "CAPTURE",
                "purchase_units": [
                    {
                        "amount": {
                            "currency_code": "USD",
                            "value": pricing["price"],
                        },
                        "description": pricing["description"],
                    }
                ],
                "application_context": {
                    "brand_name": "AEGIS Defense Platform",
                    "shipping_preference": "NO_SHIPPING",
                    "user_action": "PAY_NOW",
                },
            },
        )
        order_data = resp.json()

    if resp.status_code >= 400:
        logger.error(f"PayPal create order failed: {order_data}")
        raise HTTPException(502, "Failed to create PayPal order")

    approval_url = next(
        (l["href"] for l in order_data.get("links", []) if l["rel"] == "approve"),
        None,
    )
    return {
        "order_id": order_data["id"],
        "approval_url": approval_url,
        "tier": body.tier,
    }


@router.post("/capture-order")
async def capture_order(
    body: CaptureOrderRequest,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Capture a PayPal order after user approval and upgrade the client tier."""
    if not settings.PAYPAL_CLIENT_ID or not settings.PAYPAL_SECRET:
        raise HTTPException(503, "Payment system not configured")

    token = await get_paypal_token()

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{settings.PAYPAL_API_URL}/v2/checkout/orders/{body.order_id}/capture",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        capture_data = resp.json()

    if capture_data.get("status") != "COMPLETED":
        raise HTTPException(
            400, f"Payment not completed: {capture_data.get('status')}"
        )

    # Determine which tier was purchased from the order description
    desc = capture_data.get("purchase_units", [{}])[0].get("description", "")
    new_tier = (
        "enterprise" if "Enterprise" in desc else "pro" if "Pro" in desc else "pro"
    )
    tier_config = TIERS.get(new_tier, TIERS["pro"])

    # Upgrade client tier
    client_obj = auth.client
    client_obj.tier = new_tier
    client_obj.max_nodes = tier_config["max_nodes"]
    client_obj.max_assets = tier_config["max_assets"]
    client_obj.max_users = tier_config["max_users"]
    await db.commit()

    transaction_id = (
        capture_data.get("purchase_units", [{}])[0]
        .get("payments", {})
        .get("captures", [{}])[0]
        .get("id", "")
    )

    logger.info(
        f"Tier upgraded: {auth.client.name} -> {new_tier} (txn: {transaction_id})"
    )

    return {
        "status": "paid",
        "tier": new_tier,
        "transaction_id": transaction_id,
        "max_nodes": tier_config["max_nodes"],
        "max_assets": tier_config["max_assets"],
        "max_users": tier_config["max_users"],
    }


@router.get("/status")
async def payment_status(auth: AuthContext = Depends(require_viewer)):
    """Return the current client's tier and available upgrades."""
    client = auth.client
    return {
        "current_tier": client.tier,
        "max_nodes": client.max_nodes,
        "max_assets": client.max_assets,
        "max_users": client.max_users,
        "upgrades_available": [
            t for t in ["pro", "enterprise"] if t != client.tier
        ],
        "prices": TIER_PRICES,
        "paypal_configured": bool(settings.PAYPAL_CLIENT_ID and settings.PAYPAL_SECRET),
    }
