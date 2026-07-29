"""Tests for the refresh-token cookie's actual attributes.

TestingConfig sets REFRESH_COOKIE_SECURE = False (see app/config.py) so
the test client, which talks HTTP rather than HTTPS, can exercise the
cookie flow at all. That means the shared `client` fixture can't be used
to check that the Secure flag is present -- this file builds its own app
instance with REFRESH_COOKIE_SECURE forced back on, the same pattern
test_rate_limiting.py uses for RATELIMIT_ENABLED.
"""

import pytest

from app import create_app
from app.extensions import db


@pytest.fixture()
def secure_client():
    app = create_app("testing")
    app.config["REFRESH_COOKIE_SECURE"] = True

    with app.app_context():
        from app import models  # noqa: F401

        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def _login(client, email="cookie@example.com", password="CorrectHorseBatteryStaple9!"):
    client.post("/auth/register", json={"email": email, "password": password})
    return client.post("/auth/login", json={"email": email, "password": password})


def test_refresh_cookie_is_httponly(client):
    resp = _login(client)

    assert "HttpOnly" in resp.headers.get("Set-Cookie", "")


def test_refresh_cookie_is_samesite_strict(client):
    resp = _login(client)

    assert "SameSite=Strict" in resp.headers.get("Set-Cookie", "")


def test_refresh_cookie_is_scoped_to_auth_path(client):
    resp = _login(client)

    assert "Path=/auth" in resp.headers.get("Set-Cookie", "")


def test_refresh_cookie_is_secure_when_configured(secure_client):
    resp = _login(secure_client)

    assert "Secure" in resp.headers.get("Set-Cookie", "")


def test_refresh_cookie_not_readable_from_json_response_body(client):
    resp = _login(client)

    # The whole point of the cookie migration: the token must not be
    # duplicated into a place JavaScript can read it.
    assert "refresh_token" not in resp.get_json()


def test_refresh_cookie_max_age_matches_the_configured_ttl(client, app):
    resp = _login(client)

    ttl = app.config["JWT_REFRESH_TOKEN_TTL_SECONDS"]
    assert f"Max-Age={ttl}" in resp.headers.get("Set-Cookie", "")
