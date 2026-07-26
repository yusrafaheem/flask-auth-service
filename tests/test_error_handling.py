"""Tests for generic error handling and enumeration resistance.

The 500-path in app/errors.py isn't exercised here: Flask's TESTING=True
config makes PROPAGATE_EXCEPTIONS default to True, so an unhandled
exception raised inside a view is re-raised to the test client instead
of being turned into a response -- that's Flask's own test-debugging
behavior, not a gap in the handler itself. The HTTPException path (404,
405) doesn't have that problem, since Flask always routes those through
registered handlers regardless of TESTING, so those are covered directly
below.
"""


def test_unknown_route_returns_json_not_html(client):
    resp = client.get("/this-route-does-not-exist")

    assert resp.status_code == 404
    assert resp.content_type == "application/json"
    assert resp.get_json() == {"error": "Not Found"}


def test_wrong_method_on_a_real_route_returns_json_405(client):
    # /auth/login only accepts POST.
    resp = client.get("/auth/login")

    assert resp.status_code == 405
    assert resp.content_type == "application/json"
    assert resp.get_json()["error"] == "Method Not Allowed"


def test_login_gives_identical_response_for_unknown_email_and_wrong_password(client):
    """Enumeration-resistance regression guard: both failure modes must
    be indistinguishable from the response alone.
    """
    client.post("/auth/register", json={"email": "known@example.com", "password": "CorrectHorseBatteryStaple9!"})

    unknown_resp = client.post("/auth/login", json={"email": "unknown@example.com", "password": "whatever9!"})
    wrong_password_resp = client.post("/auth/login", json={"email": "known@example.com", "password": "whatever9!"})

    assert unknown_resp.status_code == wrong_password_resp.status_code == 401
    assert unknown_resp.get_json() == wrong_password_resp.get_json()


def test_password_reset_request_gives_identical_response_for_known_and_unknown_email(client):
    client.post("/auth/register", json={"email": "known2@example.com", "password": "CorrectHorseBatteryStaple9!"})

    known_resp = client.post("/auth/password-reset/request", json={"email": "known2@example.com"})
    unknown_resp = client.post("/auth/password-reset/request", json={"email": "unknown2@example.com"})

    assert known_resp.status_code == unknown_resp.status_code == 200
    # The known-email response legitimately carries an extra reset_token
    # field (demo-scope only, see password_reset.py's module docstring)
    # -- the message field, which is all an attacker gets to see in a
    # real deployment, must still match exactly either way.
    assert known_resp.get_json()["message"] == unknown_resp.get_json()["message"]


def test_malformed_json_body_does_not_leak_a_traceback(client):
    resp = client.post(
        "/auth/register",
        data="not-valid-json{{{",
        content_type="application/json",
    )

    # marshmallow's schema.load(None or {}) path handles a body that
    # failed to parse as JSON at all (request.get_json(silent=True)
    # returns None) the same as an empty body -- a clean validation
    # error, not a raw JSONDecodeError traceback.
    assert resp.status_code == 400
    body = resp.get_json()
    assert "Traceback" not in str(body)
