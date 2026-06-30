"""Content generator for deception campaigns.

Produces realistic fake JSON / CSV / HTML tailored to a campaign theme.

Strategy
--------
1. If an OpenRouter API key is configured and the caller supplies
   ``use_ai=True``, delegate to the ``decoy_content`` model for an AI
   response.
2. Otherwise (or if AI fails) fall back to ``Faker`` with theme-aware
   presets.  This keeps deployments resilient even when no AI provider
   is attached.

Every record produced by :meth:`ContentGenerator.fake_users` is seeded with
a breadcrumb UUID so the tracker can match it later.  Breadcrumb minting
happens outside this module — the generator just weaves placeholders.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import random
import string
import uuid
from datetime import datetime, timedelta
from typing import Any, Callable, Optional

from app.services.honey_ai.campaign import ThemeConfig
from app.services.honey_ai.themes import get_theme

logger = logging.getLogger("aegis.honey_ai.content")


# ---------------------------------------------------------------------------
# Faker import is optional — if the package is missing we degrade gracefully.
# ---------------------------------------------------------------------------

try:  # pragma: no cover - tiny import guard
    from faker import Faker  # type: ignore
    _FAKER_AVAILABLE = True
except Exception:  # pragma: no cover
    _FAKER_AVAILABLE = False
    Faker = None  # type: ignore


# ---------------------------------------------------------------------------
# OpenRouter client is optional too — guarded so unit tests don't need it.
# ---------------------------------------------------------------------------

try:  # pragma: no cover
    from app.core.openrouter import openrouter_client
    _OR_AVAILABLE = True
except Exception:  # pragma: no cover
    _OR_AVAILABLE = False
    openrouter_client = None  # type: ignore


class _MiniFaker:
    """Tiny deterministic replacement if Faker isn't installed.

    Good enough to keep content_generator functional in environments where
    the dependency hasn't been installed yet (e.g. first boot before
    ``pip install -r requirements.txt``).
    """

    _FIRST = ["James", "Sarah", "Michael", "Emma", "David", "Olivia", "Daniel",
              "Sophia", "Robert", "Ava", "Carlos", "Lin", "Amit", "Nadia"]
    _LAST = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
             "Miller", "Davis", "Rodriguez", "Martinez", "Nakamura", "Patel"]
    _STREETS = ["Main St", "Oak Ave", "Maple Dr", "Elm St", "Sunset Blvd"]
    _CITIES = ["Austin", "Seattle", "Miami", "Boston", "Denver", "Portland"]
    _STATES = ["TX", "WA", "FL", "MA", "CO", "OR"]

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rand = random.Random(seed)

    def first_name(self) -> str:
        return self._rand.choice(self._FIRST)

    def last_name(self) -> str:
        return self._rand.choice(self._LAST)

    def name(self) -> str:
        return f"{self.first_name()} {self.last_name()}"

    def user_name(self) -> str:
        return f"{self.first_name().lower()}.{self.last_name().lower()}"

    def email(self) -> str:
        return f"{self.user_name()}@example.com"

    def street_address(self) -> str:
        n = self._rand.randint(10, 9999)
        return f"{n} {self._rand.choice(self._STREETS)}"

    def city(self) -> str:
        return self._rand.choice(self._CITIES)

    def state_abbr(self) -> str:
        return self._rand.choice(self._STATES)

    def postcode(self) -> str:
        return f"{self._rand.randint(10000, 99999)}"

    def phone_number(self) -> str:
        return f"+1-{self._rand.randint(200, 999)}-{self._rand.randint(200, 999)}-{self._rand.randint(1000, 9999)}"

    def ssn(self) -> str:
        return f"{self._rand.randint(100, 999)}-{self._rand.randint(10, 99)}-{self._rand.randint(1000, 9999)}"

    def credit_card_number(self) -> str:
        return "4" + "".join(self._rand.choices(string.digits, k=15))

    def iban(self) -> str:
        return "DE" + "".join(self._rand.choices(string.digits, k=20))

    def sha256(self) -> str:
        return "".join(self._rand.choices("0123456789abcdef", k=64))

    def uuid4(self) -> str:
        return str(uuid.UUID(int=self._rand.getrandbits(128)))

    def date_this_year(self) -> datetime:
        return datetime.utcnow() - timedelta(days=self._rand.randint(0, 365))

    def word(self) -> str:
        return "".join(self._rand.choices(string.ascii_lowercase, k=self._rand.randint(4, 10)))


def _get_faker(locale: str = "en_US") -> Any:
    """Return a ``Faker`` instance if available, otherwise a mini fallback."""
    if _FAKER_AVAILABLE and Faker is not None:  # pragma: no cover
        try:
            return Faker(locale)
        except Exception:
            return Faker()
    return _MiniFaker()


# ---------------------------------------------------------------------------
# Content generator
# ---------------------------------------------------------------------------


class ContentGenerator:
    """Produces realistic fake content for deception campaigns."""

    def __init__(self) -> None:
        self._faker = _get_faker()

    # ------------------------------------------------------------------
    # Structured fake data — the workhorse for smart_api/smart_db decoys
    # ------------------------------------------------------------------

    def fake_users(
        self,
        theme: ThemeConfig | str,
        count: int = 50,
        breadcrumb_provider: Optional[Callable[[str, str], str]] = None,
    ) -> list[dict]:
        """Return ``count`` fake user records shaped for *theme*.

        If ``breadcrumb_provider(bait_kind, preview)`` is supplied it is
        called every time a breadcrumbable value is minted — typically the
        email address and an API key field.  The returned breadcrumb UUID
        is woven into the record.  This lets the orchestrator persist the
        breadcrumbs in the ``HoneyBreadcrumb`` table in one atomic pass.
        """
        theme_cfg = theme if isinstance(theme, ThemeConfig) else get_theme(theme)
        faker = self._faker
        users: list[dict] = []

        for i in range(1, count + 1):
            first = faker.first_name()
            last = faker.last_name()
            username = f"{first.lower()}.{last.lower()}"
            # Use theme-specific domains so the fake universe looks internal.
            domain = random.choice(theme_cfg.fake_domains or ["internal.corp"])
            email = f"{username}@{domain}"
            if breadcrumb_provider:
                breadcrumb_provider("email", email)

            api_key = f"ak_live_{''.join(random.choices(string.ascii_letters + string.digits, k=32))}"
            if breadcrumb_provider:
                breadcrumb_provider("api_key", api_key[:20])

            record: dict[str, Any] = {
                "id": i,
                "username": username,
                "email": email,
                "name": f"{first} {last}",
                "role": random.choice(["admin", "user", "editor", "viewer", "manager"]),
                "active": random.random() > 0.15,
                "api_key": api_key,
                "last_login": (
                    datetime.utcnow()
                    - timedelta(hours=random.randint(1, 720))
                ).isoformat(),
                "created_at": (
                    datetime.utcnow()
                    - timedelta(days=random.randint(30, 900))
                ).isoformat(),
            }

            if theme_cfg.name == "fintech":
                card = faker.credit_card_number()
                if breadcrumb_provider:
                    breadcrumb_provider("card_number", card[-4:])
                record.update({
                    "account_balance_usd": round(random.uniform(100.0, 50000.0), 2),
                    "card_last4": card[-4:],
                    "iban": faker.iban(),
                    "kyc_status": random.choice(["verified", "pending", "rejected"]),
                })
            elif theme_cfg.name == "healthcare":
                patient_id = f"PT-{uuid.uuid4().hex[:10].upper()}"
                if breadcrumb_provider:
                    breadcrumb_provider("patient_id", patient_id)
                record.update({
                    "patient_id": patient_id,
                    "insurance_id": f"INS-{random.randint(100000, 999999)}",
                    "diagnosis_code": random.choice(["E11.9", "I10", "J45.909", "M54.5"]),
                    "medication": random.choice(["Metformin", "Lisinopril", "Atorvastatin"]),
                })
            elif theme_cfg.name == "ecommerce":
                record.update({
                    "total_orders": random.randint(0, 120),
                    "lifetime_value_usd": round(random.uniform(0, 25000), 2),
                    "preferred_category": random.choice(["electronics", "apparel", "home", "books"]),
                })
            elif theme_cfg.name == "devops":
                record.update({
                    "ssh_key_fingerprint": f"SHA256:{uuid.uuid4().hex[:43]}",
                    "team": random.choice(["platform", "sre", "data", "security"]),
                    "github_handle": username,
                })

            users.append(record)
        return users

    def fake_rows(
        self,
        theme: ThemeConfig | str,
        table: str,
        count: int = 25,
        breadcrumb_provider: Optional[Callable[[str, str], str]] = None,
    ) -> list[dict]:
        """Generic row generator used by the smart DB honeypot."""
        theme_cfg = theme if isinstance(theme, ThemeConfig) else get_theme(theme)
        t = table.lower()
        if t in {"users", "accounts", "customers"}:
            return self.fake_users(theme_cfg, count, breadcrumb_provider)

        rows: list[dict] = []
        for i in range(1, count + 1):
            if t == "orders":
                rows.append({
                    "id": 1000 + i,
                    "user_id": random.randint(1, 50),
                    "status": random.choice(["pending", "paid", "shipped", "cancelled"]),
                    "amount_usd": round(random.uniform(10, 1500), 2),
                    "created_at": (
                        datetime.utcnow() - timedelta(days=random.randint(0, 180))
                    ).isoformat(),
                })
            elif t in {"payments", "transactions", "invoices"}:
                rows.append({
                    "id": 5000 + i,
                    "customer_id": random.randint(1, 500),
                    "amount_usd": round(random.uniform(5, 5000), 2),
                    "method": random.choice(["card", "ach", "wire", "paypal"]),
                    "status": random.choice(["captured", "refunded", "pending"]),
                    "processor": random.choice(["stripe", "adyen", "braintree"]),
                })
            elif t in {"products", "skus", "inventory"}:
                rows.append({
                    "id": 2000 + i,
                    "sku": f"SKU-{random.randint(10000, 99999)}",
                    "name": f"Product {i}",
                    "price_usd": round(random.uniform(5, 999), 2),
                    "stock": random.randint(0, 500),
                })
            elif t in {"sessions", "tokens"}:
                token = f"tok_{uuid.uuid4().hex}"
                if breadcrumb_provider:
                    breadcrumb_provider("jwt", token[:24])
                rows.append({
                    "id": i,
                    "user_id": random.randint(1, 500),
                    "token": token,
                    "issued_at": datetime.utcnow().isoformat(),
                    "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat(),
                })
            else:
                rows.append({"id": i, "value": f"{theme_cfg.name}_{table}_{i}"})
        return rows

    def fake_csv(
        self,
        theme: ThemeConfig | str,
        rows: int = 50,
        breadcrumb_provider: Optional[Callable[[str, str], str]] = None,
    ) -> str:
        """CSV export — used as a "customer_list.csv" decoy file."""
        records = self.fake_users(theme, rows, breadcrumb_provider)
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(records[0].keys()) if records else ["id"])
        writer.writeheader()
        for r in records:
            writer.writerow(r)
        return buf.getvalue()

    def fake_config(self, theme: ThemeConfig | str) -> dict:
        theme_cfg = theme if isinstance(theme, ThemeConfig) else get_theme(theme)
        return {
            "app": {
                "name": f"{theme_cfg.label} Admin",
                "version": f"{random.randint(2, 6)}.{random.randint(0, 20)}.{random.randint(0, 40)}",
                "environment": "production",
                "debug": False,
            },
            "database": {
                "host": random.choice(theme_cfg.fake_domains or ["db.internal"]),
                "port": 5432,
                "name": f"{theme_cfg.name}_production",
            },
            "cache": {"driver": "redis", "host": "cache.internal.prod"},
            "storage": {"driver": "s3", "bucket": f"{theme_cfg.name}-assets-prod"},
            "features": {f"new_{p.replace(' ', '_')}": random.random() > 0.5
                         for p in theme_cfg.fake_products[:4]},
        }

    # ------------------------------------------------------------------
    # AI-assisted freeform content
    # ------------------------------------------------------------------

    async def ai_snippet(
        self,
        theme: ThemeConfig | str,
        prompt: str,
        max_chars: int = 800,
    ) -> Optional[str]:
        """Try to get an AI-generated HTML/JSON snippet. Returns None on failure."""
        if not _OR_AVAILABLE or openrouter_client is None:  # pragma: no cover
            return None

        theme_cfg = theme if isinstance(theme, ThemeConfig) else get_theme(theme)
        full_prompt = (
            f"{theme_cfg.prompt_seed}\n\n"
            f"Theme: {theme_cfg.label} ({theme_cfg.industry})\n"
            f"Task: {prompt}\n"
            f"Keep output under {max_chars} characters. "
            "Return raw HTML or JSON only, no markdown fences."
        )
        try:  # pragma: no cover - network path
            result = await openrouter_client.query(
                [{"role": "user", "content": full_prompt}],
                "decoy_content",
            )
            content = (result or {}).get("content", "").strip()
            return content[:max_chars] if content else None
        except Exception as e:  # pragma: no cover
            logger.debug(f"AI decoy content failed, falling back: {e}")
            return None

    # ------------------------------------------------------------------
    # HTML shells used by smart_http for theme-aware pages
    # ------------------------------------------------------------------

    def fake_dashboard_html(self, theme: ThemeConfig | str) -> str:
        theme_cfg = theme if isinstance(theme, ThemeConfig) else get_theme(theme)
        stats = [
            (random.choice(theme_cfg.fake_products or ["Users"]).title(),
             f"{random.randint(1000, 99999):,}"),
            ("Revenue (MTD)", f"${random.randint(20000, 500000):,}"),
            ("Active Sessions", f"{random.randint(10, 2000):,}"),
            ("API Calls (24h)", f"{random.randint(10000, 9999999):,}"),
        ]
        stat_html = "".join(
            f'<div class="stat"><div class="stat-label">{label}</div>'
            f'<div class="stat-value">{value}</div></div>'
            for label, value in stats
        )
        return (
            '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
            f"<title>{theme_cfg.label} Dashboard</title>"
            "<style>*{margin:0;padding:0;box-sizing:border-box}"
            "body{background:#0a0a0a;color:#ededed;font-family:-apple-system,sans-serif}"
            ".main{padding:32px;max-width:1200px;margin:0 auto}"
            "h1{font-size:24px;margin-bottom:8px}"
            ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}"
            ".stat{background:#18181b;border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:24px}"
            ".stat-label{font-size:12px;color:#71717a;text-transform:uppercase;letter-spacing:.5px}"
            ".stat-value{font-size:28px;font-weight:700;margin-top:4px}"
            "</style></head><body>"
            f'<div class="main"><h1>{theme_cfg.label} Dashboard</h1>'
            f'<div class="grid">{stat_html}</div></div></body></html>'
        )


# Singleton — phantom modules import this rather than instantiating per call.
content_generator = ContentGenerator()
