"""Tests for POST /auth/register."""

from app.models.user import User


def test_register_with_valid_data_creates_user(client):
    resp = client.post(
        "/auth/register",
        json={"email": "new@example.com", "password": "CorrectHorseBatteryStaple9!"},
    )

    assert resp.status_code == 201
    body = resp.get_json()
    assert body["email"] == "new@example.com"
    assert "password" not in body
    assert "password_hash" not in body


def test_register_persists_user_with_hashed_password(client, app):
    client.post(
        "/auth/register",
        json={"email": "hashme@example.com", "password": "CorrectHorseBatteryStaple9!"},
    )

    with app.app_context():
        user = User.query.filter_by(email="hashme@example.com").first()
        assert user is not None
        assert user.password_hash != "CorrectHorseBatteryStaple9!"


def test_register_lowercases_email(client, app):
    client.post(
        "/auth/register",
        json={"email": "MixedCase@Example.com", "password": "CorrectHorseBatteryStaple9!"},
    )

    with app.app_context():
        assert User.query.filter_by(email="mixedcase@example.com").first() is not None


def test_register_rejects_duplicate_email(client):
    payload = {"email": "dupe@example.com", "password": "CorrectHorseBatteryStaple9!"}
    first = client.post("/auth/register", json=payload)
    second = client.post("/auth/register", json=payload)

    assert first.status_code == 201
    assert second.status_code == 409


def test_register_rejects_invalid_email(client):
    resp = client.post(
        "/auth/register",
        json={"email": "not-an-email", "password": "CorrectHorseBatteryStaple9!"},
    )

    assert resp.status_code == 400


def test_register_rejects_weak_password(client):
    resp = client.post(
        "/auth/register",
        json={"email": "weakpw@example.com", "password": "short"},
    )

    assert resp.status_code == 400
    assert "password" in resp.get_json()["errors"]


def test_register_rejects_missing_body(client):
    resp = client.post("/auth/register")

    assert resp.status_code == 400


def test_register_rejects_duplicate_email_case_insensitively(client):
    client.post(
        "/auth/register",
        json={"email": "CaseDupe@Example.com", "password": "CorrectHorseBatteryStaple9!"},
    )

    resp = client.post(
        "/auth/register",
        json={"email": "casedupe@example.com", "password": "AnotherPassword9!"},
    )

    assert resp.status_code == 409
