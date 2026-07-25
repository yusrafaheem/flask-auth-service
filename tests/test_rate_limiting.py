"""Tests for rate limiting on login/register/password-reset-request.

The shared `app`/`client` fixtures use TestingConfig, which sets
RATELIMIT_ENABLED = False (see app/config.py) -- that's deliberate, so
every other test file in this suite isn't accidentally rate-limited by
looping over requests. To actually exercise rate limiting for real, this
file builds its own app instance with limiting turned back on, rather
than changing the shared fixture's behavior for everyone else.
"""

import pytest

from app import create_app
from app.extensions import db, limiter


@pytest.fixture()
def limited_client():
    app = create_app("testing")
    app.config["RATELIMIT_ENABLED"] = True

    with app.app_context():
        from app import models  # noqa: F401

        db.create_all()
        limiter.reset()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def test_login_endpoint_enforces_rate_limit(limited_client):
    payload = {"email": "ratelimit@example.com", "password": "WrongPassword9!"}

    # The limit is 10/minute (see app/routes/auth.py); the 11th request
    # from the same client should be throttled.
    responses = [limited_client.post("/auth/login", json=payload) for _ in range(11)]

    assert responses[-1].status_code == 429
    assert any(r.status_code == 401 for r in responses[:10])


def test_register_endpoint_enforces_rate_limit(limited_client):
    def _payload(i):
        return {"email": f"rl{i}@example.com", "password": "CorrectHorseBatteryStaple9!"}

    # The limit is 10/hour (see app/routes/auth.py).
    responses = [limited_client.post("/auth/register", json=_payload(i)) for i in range(11)]

    assert responses[-1].status_code == 429


def test_password_reset_request_enforces_rate_limit(limited_client):
    payload = {"email": "rl-reset@example.com"}

    # The limit is 5/hour (see app/routes/password_reset.py).
    responses = [
        limited_client.post("/auth/password-reset/request", json=payload) for _ in range(6)
    ]

    assert responses[-1].status_code == 429
