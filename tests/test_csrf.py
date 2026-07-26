"""Tests for the double-submit-cookie CSRF protection itself.

test_refresh_logout.py exercises /auth/refresh and /auth/logout under the
*happy* CSRF path (matching cookie + header). This file exercises the
CSRF gate in isolation: missing header, missing cookie, and a
header/cookie pair that doesn't match -- plus the two "no session at
all" scenarios that got dropped from test_refresh_logout.py once those
routes started requiring a CSRF pair to reach their body.
"""

import re

from app.models.refresh_token import RefreshToken


def _extract_cookie_value(response, cookie_name):
    for header in response.headers.getlist("Set-Cookie"):
        match = re.match(rf"{cookie_name}=([^;]*)", header)
        if match:
            return match.group(1)
    return None


def _register_and_login(client, email="csrf@example.com", password="CorrectHorseBatteryStaple9!"):
    client.post("/auth/register", json={"email": email, "password": password})
    return client.post("/auth/login", json={"email": email, "password": password})


def test_refresh_with_no_csrf_header_at_all_returns_403(client):
    _register_and_login(client)

    # The refresh_token cookie is present (the test client's cookie jar
    # attached it automatically) but no X-CSRF-Token header was sent.
    resp = client.post("/auth/refresh")

    assert resp.status_code == 403


def test_logout_with_no_csrf_header_at_all_returns_403(client):
    _register_and_login(client)

    resp = client.post("/auth/logout")

    assert resp.status_code == 403


def test_refresh_with_mismatched_csrf_header_returns_403(client):
    login_resp = _register_and_login(client)
    real_csrf = _extract_cookie_value(login_resp, "csrf_token")
    assert real_csrf is not None

    resp = client.post("/auth/refresh", headers={"X-CSRF-Token": real_csrf + "-tampered"})

    assert resp.status_code == 403


def test_logout_with_mismatched_csrf_header_returns_403(client):
    login_resp = _register_and_login(client)
    real_csrf = _extract_cookie_value(login_resp, "csrf_token")
    assert real_csrf is not None

    resp = client.post("/auth/logout", headers={"X-CSRF-Token": real_csrf + "-tampered"})

    assert resp.status_code == 403


def test_refresh_csrf_check_runs_before_touching_the_refresh_token(client, app):
    """A failed CSRF check must not revoke or rotate anything.

    Regression guard for decorator ordering: @csrf_protect wraps the view,
    so a bad CSRF pair should short-circuit before any RefreshToken row is
    read or written.
    """
    login_resp = _register_and_login(client)

    client.post("/auth/refresh", headers={"X-CSRF-Token": "not-even-close"})

    with app.app_context():
        # Still exactly one refresh token on record, and it's still active
        # -- the rejected request never reached the rotation logic.
        assert RefreshToken.query.filter_by(revoked_at=None).count() == 1


def test_no_session_at_all_refresh_still_requires_csrf_first(client):
    """No cookies of any kind (never logged in). CSRF is checked first,
    so this is a 403, not the 400 "missing refresh cookie" a logged-in
    caller without a refresh cookie would get -- there's no CSRF cookie
    to match against either, so the check fails immediately.
    """
    resp = client.post("/auth/refresh", headers={"X-CSRF-Token": "anything"})

    assert resp.status_code == 403


def test_no_session_at_all_logout_still_requires_csrf_first(client):
    resp = client.post("/auth/logout", headers={"X-CSRF-Token": "anything"})

    assert resp.status_code == 403
