"""End-to-end integration test: a single client walking the full
register -> login -> me -> refresh -> logout -> post-logout-me flow.

Every other test file in this suite exercises one endpoint (or one
concern, like CSRF or audit logging) in isolation with fresh state each
time. This file is the opposite on purpose: one continuous session,
asserting the pieces actually compose -- that the access token from
login authorizes /me, that the cookie login sets is the one refresh
reads, that the CSRF cookie refresh sets is the one the next refresh
needs, and that logout actually ends the session rather than just
returning 200.
"""

import re


def _extract_cookie_value(response, cookie_name):
    for header in response.headers.getlist("Set-Cookie"):
        match = re.match(rf"{cookie_name}=([^;]*)", header)
        if match:
            return match.group(1)
    return None


def test_full_register_login_me_refresh_logout_flow(client, app):
    email = "e2e@example.com"
    password = "CorrectHorseBatteryStaple9!"

    # 1. Register.
    register_resp = client.post("/auth/register", json={"email": email, "password": password})
    assert register_resp.status_code == 201
    user_id = register_resp.get_json()["id"]

    # Registering the same email again is rejected -- confirms the
    # account from step 1 is really persisted, not just returned once.
    dup_resp = client.post("/auth/register", json={"email": email, "password": password})
    assert dup_resp.status_code == 409

    # 2. Login. The test client's cookie jar picks up refresh_token and
    # csrf_token automatically from here on; we only need to read the
    # csrf_token value back out to echo it in headers later.
    login_resp = client.post("/auth/login", json={"email": email, "password": password})
    assert login_resp.status_code == 200
    access_token = login_resp.get_json()["access_token"]
    assert "refresh_token" in login_resp.headers.get("Set-Cookie", "")
    csrf_token = _extract_cookie_value(login_resp, "csrf_token")
    assert csrf_token is not None

    # 3. /me with the access token from login.
    me_resp = client.get("/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert me_resp.status_code == 200
    assert me_resp.get_json() == {"id": user_id, "email": email}

    # /me with no token at all is rejected -- confirms auth_required is
    # actually gating this route, not just happening to succeed above.
    unauthed_resp = client.get("/auth/me")
    assert unauthed_resp.status_code == 401

    # 4. Refresh: the old access token still technically hasn't expired
    # yet (short-lived, but not immediately), but the point of refresh is
    # to get a new pair without re-authenticating with a password.
    refresh_resp = client.post("/auth/refresh", headers={"X-CSRF-Token": csrf_token})
    assert refresh_resp.status_code == 200
    new_access_token = refresh_resp.get_json()["access_token"]
    assert new_access_token != access_token
    new_csrf_token = _extract_cookie_value(refresh_resp, "csrf_token")
    assert new_csrf_token is not None

    # The new access token works too.
    me_after_refresh = client.get("/auth/me", headers={"Authorization": f"Bearer {new_access_token}"})
    assert me_after_refresh.status_code == 200

    # The old CSRF token is now stale -- rotation means it no longer
    # matches the (also rotated) csrf_token cookie.
    stale_refresh_resp = client.post("/auth/refresh", headers={"X-CSRF-Token": csrf_token})
    assert stale_refresh_resp.status_code == 403

    # 5. Logout, using the current (rotated) CSRF token.
    logout_resp = client.post("/auth/logout", headers={"X-CSRF-Token": new_csrf_token})
    assert logout_resp.status_code == 200
    assert "refresh_token=" in logout_resp.headers.get("Set-Cookie", "")

    # 6. Post-logout: the refresh token is revoked, so refresh no longer
    # works even with a technically-well-formed CSRF header (the cookie
    # jar cleared refresh_token, so there's no cookie to match against
    # the DB row anyway -- and that DB row is revoked besides).
    post_logout_refresh = client.post("/auth/refresh", headers={"X-CSRF-Token": new_csrf_token})
    assert post_logout_refresh.status_code in (400, 401, 403)

    # The already-issued access token is still technically valid until
    # its own expiry (access tokens aren't revocable, by design -- only
    # refresh tokens are) -- /me still works with it. This documents
    # that tradeoff rather than treating it as a bug: short access-token
    # TTLs are what bound the exposure window, not revocation.
    me_after_logout = client.get("/auth/me", headers={"Authorization": f"Bearer {new_access_token}"})
    assert me_after_logout.status_code == 200
