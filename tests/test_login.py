"""Tests for POST /auth/login."""

from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.security.passwords import hash_password


def _make_user(app, email="user@example.com", password="CorrectHorseBatteryStaple9!"):
    with app.app_context():
        from app.extensions import db

        user = User(email=email, password_hash=hash_password(password))
        db.session.add(user)
        db.session.commit()
        return user.id


def test_login_with_correct_credentials_returns_access_token_and_sets_refresh_cookie(client, app):
    _make_user(app)

    resp = client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "CorrectHorseBatteryStaple9!"},
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert "access_token" in body
    # The refresh token no longer appears in the JSON body -- see
    # test_cookie_refresh.py for the cookie-based flow itself.
    assert "refresh_token" not in body
    assert "refresh_token" in resp.headers.get("Set-Cookie", "")


def test_login_persists_a_refresh_token_row(client, app):
    _make_user(app)

    client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "CorrectHorseBatteryStaple9!"},
    )

    with app.app_context():
        assert RefreshToken.query.count() == 1


def test_login_with_wrong_password_returns_401(client, app):
    _make_user(app)

    resp = client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "WrongPassword9!"},
    )

    assert resp.status_code == 401
    assert "access_token" not in resp.get_json()


def test_login_with_unknown_email_returns_401(client):
    resp = client.post(
        "/auth/login",
        json={"email": "nobody@example.com", "password": "CorrectHorseBatteryStaple9!"},
    )

    assert resp.status_code == 401


def test_login_unknown_email_and_wrong_password_return_identical_error_body(client, app):
    _make_user(app)

    unknown = client.post(
        "/auth/login",
        json={"email": "nobody@example.com", "password": "whatever9!X"},
    )
    wrong = client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "WrongPassword9!"},
    )

    # Same status and same body -- this is what prevents the login endpoint
    # from being usable to enumerate registered emails.
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.get_json() == wrong.get_json()


def test_login_rejects_missing_body(client):
    resp = client.post("/auth/login")

    assert resp.status_code == 401


def test_login_lowercases_email_before_lookup(client, app):
    _make_user(app, email="mixedcase@example.com")

    resp = client.post(
        "/auth/login",
        json={"email": "MixedCase@Example.com", "password": "CorrectHorseBatteryStaple9!"},
    )

    assert resp.status_code == 200


def test_login_rejects_a_deactivated_user_even_with_correct_password(client, app):
    user_id = _make_user(app, email="deactivated@example.com")

    with app.app_context():
        from app.extensions import db

        user = User.query.get(user_id)
        user.is_active = False
        db.session.commit()

    resp = client.post(
        "/auth/login",
        json={"email": "deactivated@example.com", "password": "CorrectHorseBatteryStaple9!"},
    )

    assert resp.status_code == 401
