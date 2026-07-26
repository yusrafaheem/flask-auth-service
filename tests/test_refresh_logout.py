"""Tests for POST /auth/refresh and POST /auth/logout.

Both endpoints require a valid CSRF header/cookie pair (see
app/security/csrf.py and test_csrf.py for CSRF-specific tests) in
addition to the refresh-token cookie, since this commit's earlier sibling
wired @csrf_protect onto both routes. `_csrf_headers` below pulls the
csrf_token value the login response just set so these tests can supply a
matching X-CSRF-Token, the way a real frontend would after reading the
cookie with JavaScript.
"""

import re

from app.models.refresh_token import RefreshToken


def _extract_cookie_value(response, cookie_name):
    for header in response.headers.getlist("Set-Cookie"):
        match = re.match(rf"{cookie_name}=([^;]*)", header)
        if match:
            return match.group(1)
    return None


def _register_and_login(client, email="rt@example.com", password="CorrectHorseBatteryStaple9!"):
    client.post("/auth/register", json={"email": email, "password": password})
    return client.post("/auth/login", json={"email": email, "password": password})


def _csrf_headers(login_resp):
    csrf_value = _extract_cookie_value(login_resp, "csrf_token")
    return {"X-CSRF-Token": csrf_value}


def test_refresh_with_valid_cookie_and_csrf_returns_new_access_token(client):
    login_resp = _register_and_login(client)

    resp = client.post("/auth/refresh", headers=_csrf_headers(login_resp))

    assert resp.status_code == 200
    assert "access_token" in resp.get_json()


def test_refresh_rotates_the_cookie_to_a_new_value(client):
    login_resp = _register_and_login(client)
    old_cookie_header = login_resp.headers.get("Set-Cookie", "")

    refresh_resp = client.post("/auth/refresh", headers=_csrf_headers(login_resp))
    new_cookie_header = refresh_resp.headers.get("Set-Cookie", "")

    assert new_cookie_header != ""
    assert new_cookie_header != old_cookie_header


def test_refresh_revokes_the_old_token_so_a_second_refresh_needs_the_new_csrf(client):
    login_resp = _register_and_login(client)

    first_refresh = client.post("/auth/refresh", headers=_csrf_headers(login_resp))

    # The CSRF cookie was rotated by the first refresh too -- reusing the
    # *old* CSRF header (from login) against the *new* cookie must fail.
    stale_csrf_resp = client.post("/auth/refresh", headers=_csrf_headers(login_resp))
    assert stale_csrf_resp.status_code == 403

    # Using the header from the most recent response succeeds.
    fresh_resp = client.post("/auth/refresh", headers=_csrf_headers(first_refresh))
    assert fresh_resp.status_code == 200


def test_refresh_with_garbage_cookie_returns_401(client):
    """A hand-crafted "Cookie" header here doesn't reliably override the
    test client's own cookie jar (which already holds the real
    refresh_token cookie login set) -- both end up on the request and
    the real one wins, so the request quietly succeeds instead of
    testing the garbage-token path. client.set_cookie() replaces the
    jar's value directly instead of fighting it with a second header.
    """
    login_resp = _register_and_login(client)
    csrf_headers = _csrf_headers(login_resp)

    client.set_cookie("refresh_token", "not-a-real-token")
    resp = client.post("/auth/refresh", headers=csrf_headers)

    assert resp.status_code == 401


def test_refresh_with_no_cookie_returns_400(client):
    login_resp = _register_and_login(client)
    csrf_headers = _csrf_headers(login_resp)

    # Valid CSRF pair, but no refresh_token cookie at all -- remove it
    # from the jar rather than trying to override it with an empty
    # "Cookie" header (see test_refresh_with_garbage_cookie_returns_401
    # for why that doesn't reliably work).
    client.delete_cookie("refresh_token")
    resp = client.post("/auth/refresh", headers=csrf_headers)

    assert resp.status_code == 400


def test_logout_revokes_the_refresh_token(client, app):
    login_resp = _register_and_login(client)

    resp = client.post("/auth/logout", headers=_csrf_headers(login_resp))
    assert resp.status_code == 200

    with app.app_context():
        # Logout revoked the session's only refresh token row.
        assert RefreshToken.query.filter_by(revoked_at=None).count() == 0


def test_logout_clears_the_cookie(client):
    login_resp = _register_and_login(client)

    resp = client.post("/auth/logout", headers=_csrf_headers(login_resp))

    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "refresh_token=" in set_cookie
    # A cleared cookie is expired/emptied, not just re-sent with a value.
    assert "Expires=Thu, 01-Jan-1970" in set_cookie or "Max-Age=0" in set_cookie
