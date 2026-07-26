"""Tests for the security headers applied to every response.

Deliberately checked on an arbitrary, unauthenticated route (register)
rather than a dedicated test-only route -- the whole point of wiring
apply_security_headers via app.after_request in the app factory is that
it applies uniformly, so testing it through a normal endpoint is exactly
what "no route has to opt in" means in practice.
"""


def test_response_sets_nosniff(client):
    resp = client.post("/auth/register", json={"email": "not-an-email", "password": "x"})

    assert resp.headers.get("X-Content-Type-Options") == "nosniff"


def test_response_denies_framing(client):
    resp = client.post("/auth/register", json={"email": "not-an-email", "password": "x"})

    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_response_has_restrictive_csp(client):
    resp = client.post("/auth/register", json={"email": "not-an-email", "password": "x"})

    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


def test_response_sets_hsts(client):
    resp = client.post("/auth/register", json={"email": "not-an-email", "password": "x"})

    hsts = resp.headers.get("Strict-Transport-Security", "")
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts


def test_response_sets_referrer_policy(client):
    resp = client.post("/auth/register", json={"email": "not-an-email", "password": "x"})

    assert resp.headers.get("Referrer-Policy") == "no-referrer"


def test_response_sets_restrictive_permissions_policy(client):
    resp = client.post("/auth/register", json={"email": "not-an-email", "password": "x"})

    permissions = resp.headers.get("Permissions-Policy", "")
    assert "geolocation=()" in permissions
    assert "camera=()" in permissions


def test_headers_present_even_on_error_responses(client):
    """after_request runs on error responses too (a 400 here, from the bad
    email/password payload) -- these headers protect error pages just as
    much as successful ones, maybe more.
    """
    resp = client.post("/auth/register", json={"email": "not-an-email", "password": "x"})

    assert resp.status_code == 400
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_headers_present_on_get_requests_too(client):
    resp = client.get("/auth/me")

    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
