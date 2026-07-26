"""Tests for app.security.tokens.

Runs against the module directly (no Flask app needed) -- these are pure
JWT encode/decode checks, mirroring the manual verification already done
via direct python execution while building this module.
"""

import pytest

from app.security.tokens import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
)

SECRET = "test-secret-key"


def test_access_token_round_trips():
    token = create_access_token(SECRET, user_id=1)
    payload = decode_access_token(SECRET, token)

    assert payload["sub"] == "1"
    assert payload["type"] == "access"


def test_refresh_token_round_trips_and_returns_matching_jti():
    token, jti = create_refresh_token(SECRET, user_id=1)
    payload = decode_refresh_token(SECRET, token)

    assert payload["jti"] == jti
    assert payload["type"] == "refresh"


def test_access_token_rejected_when_decoded_as_refresh():
    token = create_access_token(SECRET, user_id=1)

    with pytest.raises(TokenError):
        decode_refresh_token(SECRET, token)


def test_refresh_token_rejected_when_decoded_as_access():
    token, _jti = create_refresh_token(SECRET, user_id=1)

    with pytest.raises(TokenError):
        decode_access_token(SECRET, token)


def test_tampered_token_is_rejected():
    token = create_access_token(SECRET, user_id=1)
    tampered = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")

    with pytest.raises(TokenError):
        decode_access_token(SECRET, tampered)


def test_token_signed_with_wrong_secret_is_rejected():
    token = create_access_token(SECRET, user_id=1)

    with pytest.raises(TokenError):
        decode_access_token("a-different-secret", token)


def test_different_users_get_different_jtis():
    _token1, jti1 = create_refresh_token(SECRET, user_id=1)
    _token2, jti2 = create_refresh_token(SECRET, user_id=1)

    # Two tokens for the same user still get distinct jtis -- each login
    # session needs its own revocable identity, even for the same user.
    assert jti1 != jti2
