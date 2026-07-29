"""Tests that the auth and password-reset flows actually leave an audit
trail -- not just that the endpoints return the right status codes.

Reads AuditLog rows directly rather than exposing them through an API,
since there's no admin endpoint for browsing the audit log in this
project's scope; the point of these tests is that record_event() calls
were wired into the right places, not that there's a UI for them yet.
"""

from app.models.audit_log import AuditLog


def _register(client, email="audit@example.com", password="CorrectHorseBatteryStaple9!"):
    return client.post("/auth/register", json={"email": email, "password": password})


def _events(app, event_type):
    with app.app_context():
        return AuditLog.query.filter_by(event_type=event_type).all()


def test_register_writes_an_audit_row(client, app):
    _register(client)

    rows = _events(app, "register")
    assert len(rows) == 1
    assert rows[0].email_at_time == "audit@example.com"
    assert rows[0].user_id is not None


def test_successful_login_writes_an_audit_row(client, app):
    _register(client)
    client.post("/auth/login", json={"email": "audit@example.com", "password": "CorrectHorseBatteryStaple9!"})

    rows = _events(app, "login_success")
    assert len(rows) == 1


def test_failed_login_with_wrong_password_writes_an_audit_row(client, app):
    _register(client)
    client.post("/auth/login", json={"email": "audit@example.com", "password": "WrongPassword9!"})

    rows = _events(app, "login_failure")
    assert len(rows) == 1
    assert rows[0].user_id is not None


def test_failed_login_with_unknown_email_writes_an_audit_row_with_no_user_id(client, app):
    client.post("/auth/login", json={"email": "nobody@example.com", "password": "WrongPassword9!"})

    rows = _events(app, "login_failure")
    assert len(rows) == 1
    assert rows[0].user_id is None
    assert rows[0].email_at_time == "nobody@example.com"


def test_logout_writes_an_audit_row(client, app):
    login_resp = _register_and_login(client)
    csrf = _extract_cookie_value(login_resp, "csrf_token")

    client.post("/auth/logout", headers={"X-CSRF-Token": csrf})

    rows = _events(app, "logout")
    assert len(rows) == 1


def test_password_reset_request_and_confirm_each_write_an_audit_row(client, app):
    _register(client)

    resp = client.post("/auth/password-reset/request", json={"email": "audit@example.com"})
    token = resp.get_json()["reset_token"]

    assert len(_events(app, "password_reset_requested")) == 1

    client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "ANewStrongerPassw0rd!"},
    )

    assert len(_events(app, "password_reset_confirmed")) == 1


# -- helpers duplicated (rather than imported) from test_refresh_logout.py
# on purpose: this file should stay readable/runnable on its own, and the
# duplication is a handful of lines, not a maintenance burden.


def _extract_cookie_value(response, cookie_name):
    import re

    for header in response.headers.getlist("Set-Cookie"):
        match = re.match(rf"{cookie_name}=([^;]*)", header)
        if match:
            return match.group(1)
    return None


def _register_and_login(client, email="audit@example.com", password="CorrectHorseBatteryStaple9!"):
    client.post("/auth/register", json={"email": email, "password": password})
    return client.post("/auth/login", json={"email": email, "password": password})


def test_locked_out_login_attempt_writes_an_audit_row(client, app):
    from app.security.lockout import MAX_FAILED_ATTEMPTS

    _register(client, email="lockout-audit@example.com")
    for _ in range(MAX_FAILED_ATTEMPTS):
        client.post(
            "/auth/login",
            json={"email": "lockout-audit@example.com", "password": "WrongPassword9!"},
        )

    # The account is now locked -- one more attempt (even with the right
    # password) should log a distinct "login_locked_out" event rather than
    # another "login_failure".
    client.post(
        "/auth/login",
        json={"email": "lockout-audit@example.com", "password": "CorrectHorseBatteryStaple9!"},
    )

    rows = _events(app, "login_locked_out")
    assert len(rows) == 1
