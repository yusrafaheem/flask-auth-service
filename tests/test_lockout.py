"""Tests for account lockout, exercised through POST /auth/login."""

from app.security.lockout import MAX_FAILED_ATTEMPTS


def _register(client, email="lockout@example.com", password="CorrectHorseBatteryStaple9!"):
    client.post("/auth/register", json={"email": email, "password": password})
    return email, password


def test_account_not_locked_after_a_single_failed_attempt(client):
    email, _password = _register(client)

    client.post("/auth/login", json={"email": email, "password": "WrongPassword9!"})
    resp = client.post("/auth/login", json={"email": email, "password": "WrongPassword9!"})

    assert resp.status_code == 401  # not 423 yet


def test_account_locks_after_max_failed_attempts(client):
    email, _password = _register(client)

    for _ in range(MAX_FAILED_ATTEMPTS):
        client.post("/auth/login", json={"email": email, "password": "WrongPassword9!"})

    resp = client.post("/auth/login", json={"email": email, "password": "WrongPassword9!"})
    assert resp.status_code == 423


def test_locked_account_rejects_even_the_correct_password(client):
    email, password = _register(client)

    for _ in range(MAX_FAILED_ATTEMPTS):
        client.post("/auth/login", json={"email": email, "password": "WrongPassword9!"})

    # Once locked, even the *correct* password must not succeed.
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 423


def test_successful_login_resets_failed_attempt_counter(client, app):
    email, password = _register(client)

    # A couple of failures, but not enough to lock.
    client.post("/auth/login", json={"email": email, "password": "WrongPassword9!"})
    client.post("/auth/login", json={"email": email, "password": "WrongPassword9!"})

    good = client.post("/auth/login", json={"email": email, "password": password})
    assert good.status_code == 200

    with app.app_context():
        from app.models.user import User

        user = User.query.filter_by(email=email).first()
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
