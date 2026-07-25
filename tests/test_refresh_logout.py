"""Tests for POST /auth/refresh and POST /auth/logout."""

from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.security.passwords import hash_password


def _register_and_login(client, email="rt@example.com", password="CorrectHorseBatteryStaple9!"):
    client.post("/auth/register", json={"email": email, "password": password})
    resp = client.post("/auth/login", json={"email": email, "password": password})
    return resp.get_json()


def test_refresh_with_valid_token_returns_new_token_pair(client):
    tokens = _register_and_login(client)

    resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})

    assert resp.status_code == 200
    body = resp.get_json()
    assert "access_token" in body
    assert "refresh_token" in body
    # Rotation: the new refresh token must not be the same string as the old one.
    assert body["refresh_token"] != tokens["refresh_token"]


def test_refresh_revokes_the_old_token_so_it_cannot_be_reused(client, app):
    tokens = _register_and_login(client)

    client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})

    # Reusing the same (now-rotated-away) refresh token must fail.
    reuse_resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert reuse_resp.status_code == 401


def test_refresh_with_garbage_token_returns_401(client):
    resp = client.post("/auth/refresh", json={"refresh_token": "not-a-real-token"})

    assert resp.status_code == 401


def test_refresh_with_access_token_instead_of_refresh_token_returns_401(client):
    tokens = _register_and_login(client)

    # access_token is a different token *type* -- must be rejected here.
    resp = client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]})

    assert resp.status_code == 401


def test_refresh_with_missing_body_returns_400(client):
    resp = client.post("/auth/refresh")

    assert resp.status_code == 400


def test_logout_revokes_the_refresh_token(client, app):
    tokens = _register_and_login(client)

    resp = client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 200

    # The revoked token can no longer be used to refresh.
    refresh_resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh_resp.status_code == 401


def test_logout_is_idempotent_for_unknown_tokens(client):
    # Logging out with a bogus token still returns 200 -- the end state
    # (no usable session for that token) is the same either way.
    resp = client.post("/auth/logout", json={"refresh_token": "not-a-real-token"})

    assert resp.status_code == 200


def test_logout_twice_with_same_token_both_succeed(client):
    tokens = _register_and_login(client)

    first = client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    second = client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})

    assert first.status_code == 200
    assert second.status_code == 200
