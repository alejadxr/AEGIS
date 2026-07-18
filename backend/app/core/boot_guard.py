"""
Boot-time guard against booting AEGIS in production with default secrets.

Historically `main.py` only logged a `logger.critical(...)` warning when
`AEGIS_SECRET_KEY` still had its public default value -- boot continued
regardless (P0-9). This module makes that condition fatal in production,
and also refuses to boot with an unchanged default admin password.

Kept dependency-free (no FastAPI / SQLAlchemy imports) so it can be unit
tested in isolation and imported early during `lifespan()`.
"""

# Must match app.config.Settings.AEGIS_SECRET_KEY default exactly.
DEFAULT_SECRET = "aegis-dev-secret-key-change-in-production"

# Must match the default used in app.core.auth.seed_default_admin()
# (os.environ.get("AEGIS_ADMIN_PASSWORD", "changeme-on-first-login")).
DEFAULT_ADMIN_PASSWORD = "changeme-on-first-login"


def assert_production_secrets(
    env: str,
    secret_key: str,
    admin_password: str,
    default_admin_password: str = DEFAULT_ADMIN_PASSWORD,
) -> None:
    """
    Raise RuntimeError if running in production with default secrets.

    No-op for any env other than "production" (e.g. "development", "test").

    Args:
        env: current AEGIS_ENV value.
        secret_key: current AEGIS_SECRET_KEY value.
        admin_password: the admin password that would be seeded
            (e.g. os.environ.get("AEGIS_ADMIN_PASSWORD", default_admin_password)).
        default_admin_password: the known default admin password to compare against.
    """
    if env != "production":
        return

    bad = []
    if secret_key == DEFAULT_SECRET:
        bad.append("AEGIS_SECRET_KEY")
    if admin_password == default_admin_password:
        bad.append("AEGIS_ADMIN_PASSWORD")

    if bad:
        raise RuntimeError(
            f"Refusing to boot in production with default {', '.join(bad)}. "
            "Set strong values via env vars."
        )
