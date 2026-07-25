"""Shared extension singletons.

Kept in their own module (rather than instantiated inline in
app/__init__.py) so any module in the app -- models, routes, CLI commands
-- can `from app.extensions import db` without importing create_app and
risking a circular import. Each extension is bound to the real Flask app
via `.init_app(app)` inside create_app().

Limiter uses `RATELIMIT_STORAGE_URI` from config (default: in-process
memory) rather than a shared store like Redis. That means limits are
per-process, not shared across multiple app instances -- fine for this
project's scope (single dev/demo instance), but a real multi-instance
deployment behind a load balancer would need a shared backend so limits
apply across all instances rather than resetting per-instance. See
README for this tradeoff.

`default_limits` is a broad, generous ceiling covering every route --
the specific, tighter limits on login/register/password-reset-request are
applied per-route in app/routes/auth.py and app/routes/password_reset.py,
since those endpoints are worth throttling harder than, say, /auth/me.
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per minute"],
)
