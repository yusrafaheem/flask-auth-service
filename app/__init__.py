"""Flask application factory.

Uses the app-factory pattern (rather than a module-level `app = Flask(...)`)
specifically so tests can build a fresh, isolated app per test run with
TestingConfig and an in-memory database, instead of sharing global state
with whatever config the dev server happened to load.
"""

import os

from flask import Flask

from app.cli import register_cli
from app.config import Config, DevelopmentConfig, ProductionConfig, TestingConfig, validate_secret_key
from app.errors import register_error_handlers
from app.extensions import db, limiter
from app.routes import register_blueprints
from app.security.headers import apply_security_headers

_CONFIGS = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def create_app(config_name: str | None = None, config_overrides: dict | None = None) -> Flask:
    app = Flask(__name__)

    config_name = config_name or os.environ.get("FLASK_ENV", "development")
    app.config.from_object(_CONFIGS.get(config_name, Config))

    # Applied *before* extension init below, not after create_app()
    # returns -- Flask-Limiter in particular reads RATELIMIT_ENABLED at
    # init_app() time and fixes its storage backend accordingly, so a
    # caller mutating app.config after create_app() has already
    # returned (as test_rate_limiting.py's fixture used to) has no
    # effect on the limiter's actual behavior. This is how tests that
    # need a variant config (rate limiting force-enabled, cookie Secure
    # flag forced on) get it applied in time to matter.
    if config_overrides:
        app.config.update(config_overrides)

    # Deliberately after from_object/overrides (so it sees the real,
    # resolved SECRET_KEY) and before anything else touches the app --
    # if this raises, the process must not finish booting.
    validate_secret_key(config_name, app.config.get("SECRET_KEY"))

    db.init_app(app)
    limiter.init_app(app)

    register_cli(app)
    register_blueprints(app)
    register_error_handlers(app)

    # after_request hooks run on every response, including error responses
    # -- registered here (rather than per-blueprint) so a route added
    # later automatically gets these headers with no extra wiring.
    app.after_request(apply_security_headers)

    return app
