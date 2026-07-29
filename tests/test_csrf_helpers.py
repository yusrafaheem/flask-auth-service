"""Direct unit tests for app.security.csrf's pure functions.

test_csrf.py already covers CSRF protection through the actual HTTP routes
(refresh/logout) -- these tests instead exercise generate_csrf_token() and
csrf_token_is_valid() directly, using app.test_request_context() to fake
the cookie/header pair without needing a real login flow for each case.
"""

from app.security.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    csrf_token_is_valid,
    generate_csrf_token,
)


def test_generate_csrf_token_returns_a_string():
    token = generate_csrf_token()

    assert isinstance(token, str)
    assert len(token) > 20


def test_generate_csrf_token_produces_unique_values():
    assert generate_csrf_token() != generate_csrf_token()


def test_csrf_token_is_valid_returns_true_when_cookie_and_header_match(app):
    with app.test_request_context(
        headers={CSRF_HEADER_NAME: "matching-value"},
        environ_base={"HTTP_COOKIE": f"{CSRF_COOKIE_NAME}=matching-value"},
    ):
        assert csrf_token_is_valid() is True


def test_csrf_token_is_valid_returns_false_when_header_is_missing(app):
    with app.test_request_context(
        environ_base={"HTTP_COOKIE": f"{CSRF_COOKIE_NAME}=some-value"},
    ):
        assert csrf_token_is_valid() is False


def test_csrf_token_is_valid_returns_false_when_cookie_is_missing(app):
    with app.test_request_context(headers={CSRF_HEADER_NAME: "some-value"}):
        assert csrf_token_is_valid() is False
