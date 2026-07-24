"""Shared extension singletons.

Kept in their own module (rather than instantiated inline in
app/__init__.py) so any module in the app -- models, routes, CLI commands
-- can `from app.extensions import db` without importing create_app and
risking a circular import. Each extension is bound to the real Flask app
via `.init_app(app)` inside create_app().

Limiter's default rate is intentionally permissive here; the specific,
tighter limits for auth endpoints (login, register, password-reset
request) are configured later once those routes exist -- see this file's
later revision and app/routes/auth.py.
"""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

limiter = Limiter(key_func=get_remote_address)
