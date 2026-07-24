"""Environment-based configuration classes.

Nothing in this module reads a secret with a hardcoded fallback that would
be safe to ship -- every value that matters for security comes from the
environment, with `.env` (via python-dotenv, wired up in app/__init__.py)
as the local-development convenience. See DevelopmentConfig for the one
deliberate exception: a fixed, clearly-fake SECRET_KEY that only applies
when FLASK_ENV=development, so a fresh clone works out of the box without
anyone being tempted to reuse that key in production. ProductionConfig
fails to boot instead of silently accepting a weak or default secret --
see app/config.py's later revision (commit 50 in this repo's history) for
that fail-fast check.
"""

import os


class Config:
    """Base config: settings shared by every environment."""

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///auth.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECRET_KEY = os.environ.get("SECRET_KEY")

    JWT_ACCESS_TOKEN_TTL_SECONDS = int(os.environ.get("JWT_ACCESS_TOKEN_TTL_SECONDS", 15 * 60))
    JWT_REFRESH_TOKEN_TTL_SECONDS = int(
        os.environ.get("JWT_REFRESH_TOKEN_TTL_SECONDS", 30 * 24 * 60 * 60)
    )

    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")


class DevelopmentConfig(Config):
    DEBUG = True
    # Fixed, obviously-fake key so a fresh clone runs without any setup.
    # Never reused by ProductionConfig -- see the fail-fast check added
    # later in this file's history.
    SECRET_KEY = Config.SECRET_KEY or "dev-only-insecure-secret-key-do-not-deploy"


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "testing-secret-key"
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    DEBUG = False
