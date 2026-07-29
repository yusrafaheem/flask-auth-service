"""Tests for validate_secret_key, the fail-fast production SECRET_KEY check.

Calls validate_secret_key directly rather than through create_app("production")
-- actually booting a ProductionConfig app would also try to hit a
non-sqlite DATABASE_URL by default in some environments, which is more
than this check needs to exercise. The wiring itself (that create_app
actually calls this function) is a one-line change in app/__init__.py
that's simple enough not to need its own integration test on top of
these unit tests.
"""

import pytest

from app.config import validate_secret_key


def test_missing_secret_key_raises_in_production():
    with pytest.raises(RuntimeError, match="not set"):
        validate_secret_key("production", None)


def test_empty_secret_key_raises_in_production():
    with pytest.raises(RuntimeError, match="not set"):
        validate_secret_key("production", "")


def test_dev_default_secret_key_raises_in_production():
    with pytest.raises(RuntimeError, match="development-only default"):
        validate_secret_key("production", "dev-only-insecure-secret-key-do-not-deploy")


def test_short_secret_key_raises_in_production():
    with pytest.raises(RuntimeError, match="too short"):
        validate_secret_key("production", "short-key")


def test_strong_secret_key_passes_in_production():
    # No exception raised -- 43 chars, nothing like the dev default.
    validate_secret_key("production", "x" * 43)


def test_weak_secret_key_is_allowed_outside_production():
    # development and testing keep their intentionally-weak, fixed keys
    # so a fresh clone and the test suite run with zero setup -- this
    # check must not fire for either.
    validate_secret_key("development", "dev-only-insecure-secret-key-do-not-deploy")
    validate_secret_key("testing", "testing-secret-key")
    validate_secret_key("development", None)


def test_secret_key_of_exactly_the_minimum_length_passes():
    # 32 characters is the boundary itself (_MIN_SECRET_KEY_LENGTH) -- must
    # pass, not just anything strictly longer.
    validate_secret_key("production", "x" * 32)
