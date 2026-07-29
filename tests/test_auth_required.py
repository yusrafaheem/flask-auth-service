"""Tests for the auth_required decorator, via GET /auth/me."""

from app.models.user import User
from app.security.passwords import hash_password
from app.security.tokens import create_access_token, create_refresh_token


def _make_user(app, email="me@example.com", password="CorrectHorseBatteryStaple9!"):
    with app.app_context():
        from app.extensions import db

        user = User(email=email, password_hash=hash_password(password))
        db.session.add(user)
        db.session.commit()
        return user.id


def test_me_without_token_returns_401(client):
    resp = client.get("/auth/me")

    assert resp.status_code == 401


def test_me_with_malformed_header_returns_401(client):
    resp = client.get("/auth/me", headers={"Authorization": "not-a-bearer-token"})

    assert resp.status_code == 401


def test_me_with_valid_access_token_returns_user(client, app):
    user_id = _make_user(app)

    with app.app_context():
        token = create_access_token(app.config["SECRET_KEY"], user_id)

    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    assert resp.get_json()["email"] == "me@example.com"


def test_me_with_refresh_token_is_rejected(client, app):
    # A refresh token must not work as an access token -- auth_required
    # only decodes access tokens, so a refresh token fails type checking.
    user_id = _make_user(app)

    with app.app_context():
        token, _jti = create_refresh_token(app.config["SECRET_KEY"], user_id)

    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401


def test_me_with_token_for_deleted_user_returns_401(client, app):
    user_id = _make_user(app)

    with app.app_context():
        from app.extensions import db

        token = create_access_token(app.config["SECRET_KEY"], user_id)
        db.session.delete(User.query.get(user_id))
        db.session.commit()

    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401


def test_me_with_tampered_token_returns_401(client, app):
    user_id = _make_user(app)

    with app.app_context():
        token = create_access_token(app.config["SECRET_KEY"], user_id)

    tampered = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {tampered}"})

    assert resp.status_code == 401


def test_me_rejects_a_deactivated_user(client, app):
    user_id = _make_user(app)

    with app.app_context():
        from app.extensions import db

        user = User.query.get(user_id)
        user.is_active = False
        db.session.commit()
        token = create_access_token(app.config["SECRET_KEY"], user_id)

    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401


def test_me_with_bearer_prefix_but_empty_token_returns_401(client):
    resp = client.get("/auth/me", headers={"Authorization": "Bearer "})

    assert resp.status_code == 401


def test_me_rejects_a_token_signed_with_a_different_secret(client, app):
    user_id = _make_user(app)

    token = create_access_token("a-completely-different-secret", user_id)

    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 401
