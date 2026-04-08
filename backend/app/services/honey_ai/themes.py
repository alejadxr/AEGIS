"""Preset theme configurations for deception campaigns.

Each theme hints the content generator about the kind of industry-specific
fake data that decoys should serve (banking records, patient charts, product
orders, devops secrets, ...).  Custom themes can still be passed at runtime.
"""
from app.services.honey_ai.campaign import ThemeConfig


FINTECH = ThemeConfig(
    name="fintech",
    label="Fintech / Banking",
    description=(
        "Fake banking/payment infrastructure: accounts, wallets, KYC docs, "
        "payment processors, fraud dashboards."
    ),
    industry="financial services",
    fake_domains=[
        "bank-prod.internal",
        "payments.internal",
        "ledger-api.internal",
        "kyc-service.internal",
    ],
    fake_products=[
        "premium checking",
        "wire transfer",
        "credit card processing",
        "merchant account",
        "KYC verification",
    ],
    prompt_seed=(
        "You are generating realistic but entirely fake fintech data for a "
        "honeypot. Include account numbers, transaction amounts in USD, "
        "routing numbers, SWIFT codes, KYC statuses, and payment metadata. "
        "Never output real customer PII."
    ),
    bait_kinds=["email", "api_key", "iban", "card_number", "password"],
)


HEALTHCARE = ThemeConfig(
    name="healthcare",
    label="Healthcare / Insurance",
    description=(
        "Fake EHR / patient portal: patient records, insurance claims, "
        "medications, appointments."
    ),
    industry="healthcare",
    fake_domains=[
        "ehr-prod.internal",
        "patient-portal.internal",
        "claims.internal",
    ],
    fake_products=[
        "electronic health record",
        "insurance claim",
        "prescription",
        "lab result",
        "patient portal",
    ],
    prompt_seed=(
        "You are generating realistic but entirely fake healthcare data "
        "for a honeypot. Include patient IDs, diagnosis codes (ICD-10), "
        "medication names, insurance plan IDs, and dates. Never output real "
        "patient PII or PHI."
    ),
    bait_kinds=["email", "patient_id", "insurance_id", "api_key"],
)


ECOMMERCE = ThemeConfig(
    name="ecommerce",
    label="E-commerce / Retail",
    description=(
        "Fake online store: orders, customers, carts, payment tokens, "
        "warehouse + inventory."
    ),
    industry="retail",
    fake_domains=[
        "shop-admin.internal",
        "orders-api.internal",
        "inventory.internal",
    ],
    fake_products=[
        "order",
        "customer",
        "SKU",
        "coupon",
        "payment token",
        "warehouse shipment",
    ],
    prompt_seed=(
        "You are generating realistic but entirely fake e-commerce data for "
        "a honeypot. Include order IDs, SKUs, customer emails, shipping "
        "addresses, payment tokens, and order totals."
    ),
    bait_kinds=["email", "order_id", "card_number", "coupon_code", "api_key"],
)


DEVOPS = ThemeConfig(
    name="devops",
    label="DevOps / Infrastructure",
    description=(
        "Fake infra: CI/CD secrets, Kubernetes configs, cloud API keys, "
        "Terraform state, internal wikis."
    ),
    industry="devops",
    fake_domains=[
        "ci.internal",
        "vault.internal",
        "k8s-prod.internal",
        "registry.internal",
    ],
    fake_products=[
        "CI pipeline",
        "kubernetes cluster",
        "terraform state",
        "docker registry",
        "secrets vault",
    ],
    prompt_seed=(
        "You are generating realistic but entirely fake devops data for a "
        "honeypot. Include cloud API keys, Kubernetes secrets, CI/CD "
        "pipeline tokens, Terraform outputs, and internal service URLs. "
        "All values must be clearly fake but structurally valid."
    ),
    bait_kinds=["api_key", "ssh_key", "aws_key", "jwt", "password"],
)


THEMES: dict[str, ThemeConfig] = {
    FINTECH.name: FINTECH,
    HEALTHCARE.name: HEALTHCARE,
    ECOMMERCE.name: ECOMMERCE,
    DEVOPS.name: DEVOPS,
}


def get_theme(name: str) -> ThemeConfig:
    """Return a theme config by name, falling back to fintech."""
    return THEMES.get(name, FINTECH)
