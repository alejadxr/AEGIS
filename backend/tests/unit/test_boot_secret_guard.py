import pytest

from app.core.boot_guard import assert_production_secrets


def test_production_rejects_default_secret():
    with pytest.raises(RuntimeError):
        assert_production_secrets(
            env="production",
            secret_key="aegis-dev-secret-key-change-in-production",
            admin_password="whatever",
        )


def test_production_rejects_default_admin_password():
    with pytest.raises(RuntimeError):
        assert_production_secrets(
            env="production",
            secret_key="a-strong-random-secret",
            admin_password="changeme-on-first-login",
        )


def test_production_allows_strong_secrets():
    assert (
        assert_production_secrets(
            env="production",
            secret_key="a-strong-random-secret",
            admin_password="a-strong-random-password",
        )
        is None
    )


def test_dev_allows_default_secret():
    assert (
        assert_production_secrets(
            env="development",
            secret_key="aegis-dev-secret-key-change-in-production",
            admin_password="changeme-on-first-login",
        )
        is None
    )
