"""Flask application factory.

Uses the app-factory pattern (rather than a module-level `app = Flask(...)`)
specifically so tests can build a fresh, isolated app per test run with
TestingConfig and an in-memory database, instead of sharing global state
with whatever config the dev server happened to load.
"""

import os

from flask import Flask

from app.cli import register_cli
from app.config import Config, DevelopmentConfig, ProductionConfig, TestingConfig
from app.extensions import db, limiter
from app.routes import register_blueprints
from app.security.headers import apply_security_headers

_CONFIGS = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)

    config_name = config_name or os.environ.get("FLASK_ENV", "development")
    app.config.from_object(_CONFIGS.get(config_name, Config))

    db.init_app(app)
    limiter.init_app(app)

    register_cli(app)
    register_blueprints(app)

    # after_request hooks run on every response, including error responses
    # -- registered here (rather than per-blueprint) so a route added
    # later automatically gets these headers with no extra wiring.
    app.after_request(apply_security_headers)

    return app
