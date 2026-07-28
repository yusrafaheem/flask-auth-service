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


# The tests below exercise app.security.lockout directly, unit-style,
# against a minimal fake object -- the module only ever reads and writes
# `failed_login_attempts` and `locked_until`, so a real database-backed
# User (and the app/db fixtures a real one needs) isn't required just to
# test the lockout logic itself. The tests above already cover the same
# behavior end-to-end through POST /auth/login.


class _FakeUser:
    def __init__(self, failed_login_attempts=0, locked_until=None):
        self.failed_login_attempts = failed_login_attempts
        self.locked_until = locked_until


def test_is_locked_returns_false_when_locked_until_is_none():
    from app.security.lockout import is_locked

    user = _FakeUser(locked_until=None)

    assert is_locked(user) is False


def test_is_locked_returns_true_when_locked_until_is_in_the_future():
    from datetime import datetime, timedelta, timezone

    from app.security.lockout import is_locked

    user = _FakeUser(locked_until=datetime.now(timezone.utc) + timedelta(minutes=5))

    assert is_locked(user) is True


def test_is_locked_returns_false_once_the_lockout_window_has_passed():
    from datetime import datetime, timedelta, timezone

    from app.security.lockout import is_locked

    user = _FakeUser(locked_until=datetime.now(timezone.utc) - timedelta(seconds=1))

    assert is_locked(user) is False


def test_is_locked_treats_a_naive_locked_until_as_utc():
    from datetime import datetime, timedelta, timezone

    from app.security.lockout import is_locked

    # SQLite doesn't preserve tzinfo on round trip (see _as_aware_utc's
    # docstring in app/security/lockout.py) -- a naive datetime here must
    # still compare correctly instead of raising or silently misbehaving.
    naive_future = (datetime.now(timezone.utc) + timedelta(minutes=5)).replace(tzinfo=None)
    user = _FakeUser(locked_until=naive_future)

    assert is_locked(user) is True
