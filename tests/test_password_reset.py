"""Tests for POST /auth/password-reset/request and /confirm."""

from app.models.user import User
from app.security.passwords import verify_password


def _register(client, email="reset@example.com", password="CorrectHorseBatteryStaple9!"):
    client.post("/auth/register", json={"email": email, "password": password})
    return email, password


def test_request_for_existing_email_returns_a_token(client):
    email, _password = _register(client)

    resp = client.post("/auth/password-reset/request", json={"email": email})

    assert resp.status_code == 200
    assert "reset_token" in resp.get_json()


def test_request_for_unknown_email_returns_same_shape_without_a_token(client):
    known_resp = client.post(
        "/auth/password-reset/request", json={"email": "nobody@example.com"}
    )

    assert known_resp.status_code == 200
    assert "reset_token" not in known_resp.get_json()
    # Same top-level message either way -- this is what stops the endpoint
    # from being usable to check which emails are registered.
    assert "message" in known_resp.get_json()


def test_confirm_with_valid_token_changes_the_password(client, app):
    email, _old_password = _register(client)
    reset_resp = client.post("/auth/password-reset/request", json={"email": email})
    token = reset_resp.get_json()["reset_token"]

    resp = client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "BrandNewPassword9!"},
    )
    assert resp.status_code == 200

    with app.app_context():
        user = User.query.filter_by(email=email).first()
        assert verify_password("BrandNewPassword9!", user.password_hash) is True


def test_confirm_allows_login_with_new_password_afterward(client):
    email, _old_password = _register(client)
    reset_resp = client.post("/auth/password-reset/request", json={"email": email})
    token = reset_resp.get_json()["reset_token"]

    client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "BrandNewPassword9!"},
    )

    login_resp = client.post(
        "/auth/login", json={"email": email, "password": "BrandNewPassword9!"}
    )
    assert login_resp.status_code == 200


def test_confirm_rejects_reused_token_after_password_already_changed(client):
    email, _old_password = _register(client)
    reset_resp = client.post("/auth/password-reset/request", json={"email": email})
    token = reset_resp.get_json()["reset_token"]

    client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "BrandNewPassword9!"},
    )

    # Replaying the same token a second time must fail -- the password
    # hash it was bound to no longer matches.
    resp = client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "AnotherPassword9!"},
    )
    assert resp.status_code == 400


def test_confirm_rejects_garbage_token(client):
    resp = client.post(
        "/auth/password-reset/confirm",
        json={"token": "not-a-real-token", "new_password": "BrandNewPassword9!"},
    )

    assert resp.status_code == 400


def test_confirm_rejects_weak_new_password(client):
    email, _old_password = _register(client)
    reset_resp = client.post("/auth/password-reset/request", json={"email": email})
    token = reset_resp.get_json()["reset_token"]

    resp = client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "short"},
    )

    assert resp.status_code == 400
