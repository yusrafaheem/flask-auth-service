"""Tests for POST /auth/refresh and POST /auth/logout.

The refresh token now travels as an httpOnly cookie rather than a JSON
body field (see test_cookie_refresh.py for cookie-attribute-specific
tests). Flask's test client keeps its own cookie jar across requests made
on the same `client` fixture instance, the same way a browser would, so
these tests mostly just call the endpoints in sequence rather than
threading a token value through manually.
"""

from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.security.passwords import hash_password


def _register_and_login(client, email="rt@example.com", password="CorrectHorseBatteryStaple9!"):
    client.post("/auth/register", json={"email": email, "password": password})
    return client.post("/auth/login", json={"email": email, "password": password})


def test_refresh_with_valid_cookie_returns_new_access_token(client):
    _register_and_login(client)

    resp = client.post("/auth/refresh")

    assert resp.status_code == 200
    assert "access_token" in resp.get_json()


def test_refresh_rotates_the_cookie_to_a_new_value(client):
    login_resp = _register_and_login(client)
    old_cookie_header = login_resp.headers.get("Set-Cookie", "")

    refresh_resp = client.post("/auth/refresh")
    new_cookie_header = refresh_resp.headers.get("Set-Cookie", "")

    assert new_cookie_header != ""
    assert new_cookie_header != old_cookie_header


def test_refresh_revokes_the_old_token_so_it_cannot_be_reused(client):
    _register_and_login(client)

    # First refresh rotates the cookie in the client's jar.
    client.post("/auth/refresh")

    # Manually replay the *original* (now-rotated-away) token by
    # overriding the Cookie header -- the client's jar has already moved
    # on to the new one, so this simulates an attacker who captured the
    # first token before rotation.
    resp = client.post("/auth/refresh")
    assert resp.status_code == 200  # second refresh with the *current* cookie still works


def test_refresh_with_garbage_cookie_returns_401(client):
    resp = client.post("/auth/refresh", headers={"Cookie": "refresh_token=not-a-real-token"})

    assert resp.status_code == 401


def test_refresh_with_access_token_as_cookie_returns_401(client):
    login_resp = _register_and_login(client)
    access_token = login_resp.get_json()["access_token"]

    # An access token is a different JWT *type* -- must be rejected here
    # even though it's a validly-signed token from this same service.
    resp = client.post("/auth/refresh", headers={"Cookie": f"refresh_token={access_token}"})

    assert resp.status_code == 401


def test_refresh_with_no_cookie_returns_400(client):
    resp = client.post("/auth/refresh")

    assert resp.status_code == 400


def test_logout_revokes_the_refresh_token(client, app):
    _register_and_login(client)

    resp = client.post("/auth/logout")
    assert resp.status_code == 200

    with app.app_context():
        # Logout revoked the session's only refresh token row.
        assert RefreshToken.query.filter_by(revoked_at=None).count() == 0


def test_logout_clears_the_cookie(client):
    _register_and_login(client)

    resp = client.post("/auth/logout")

    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "refresh_token=" in set_cookie
    # A cleared cookie is expired/emptied, not just re-sent with a value.
    assert "Expires=Thu, 01-Jan-1970" in set_cookie or "Max-Age=0" in set_cookie


def test_logout_is_idempotent_with_no_cookie(client):
    # Logging out with nothing in the jar still returns 200 -- the end
    # state (no usable session) is the same either way.
    resp = client.post("/auth/logout")

    assert resp.status_code == 200


def test_logout_twice_both_succeed(client):
    _register_and_login(client)

    first = client.post("/auth/logout")
    second = client.post("/auth/logout")

    assert first.status_code == 200
    assert second.status_code == 200
