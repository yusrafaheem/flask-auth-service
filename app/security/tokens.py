"""JWT access/refresh token generation and decoding.

HS256 (symmetric) rather than RS256 is used deliberately: this service is
both the issuer and the only verifier of its own tokens, so there's no need
for asymmetric keys -- those matter when a *different* service needs to
verify tokens without being able to mint them. If this auth service is ever
split so other services verify tokens independently, that's the point to
switch to RS256.

Access and refresh tokens are both JWTs but serve different purposes and
carry a `type` claim so one can never be silently accepted as the other:
`decode_token` is deliberately not exposed to route code un-checked -- see
`decode_access_token` / `decode_refresh_token` below.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt

ACCESS_TOKEN_TTL = timedelta(minutes=15)
REFRESH_TOKEN_TTL = timedelta(days=30)
RESET_TOKEN_TTL = timedelta(minutes=30)

ALGORITHM = "HS256"


class TokenError(Exception):
    """Raised for any invalid, expired, tampered, or wrong-type token."""


def _encode(
    secret_key: str,
    user_id: int,
    token_type: str,
    ttl: timedelta,
    extra_claims: dict | None = None,
) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "iat": now,
        "exp": now + ttl,
        "jti": jti,
        **(extra_claims or {}),
    }
    token = jwt.encode(payload, secret_key, algorithm=ALGORITHM)
    return token, jti


def create_access_token(secret_key: str, user_id: int) -> str:
    token, _jti = _encode(secret_key, user_id, "access", ACCESS_TOKEN_TTL)
    return token


def create_refresh_token(secret_key: str, user_id: int) -> tuple[str, str]:
    """Returns (token, jti). The jti is persisted server-side (RefreshToken
    table) so refresh tokens can be revoked -- a bare JWT can't be revoked
    by itself since it's self-contained and valid until it expires.
    """
    return _encode(secret_key, user_id, "refresh", REFRESH_TOKEN_TTL)


def create_reset_token(secret_key: str, user_id: int, password_hash: str) -> str:
    """Password-reset token, bound to a fingerprint of the *current*
    password hash (not the hash itself -- see `_hash_fingerprint`).

    Binding to the current hash means: (1) once the password is actually
    changed, every reset token issued before that change stops verifying,
    with no separate revocation table needed, and (2) a reset token can't
    be replayed to reset the password a second time after it's already
    been used once.
    """
    fingerprint = _hash_fingerprint(password_hash)
    token, _jti = _encode(
        secret_key, user_id, "reset", RESET_TOKEN_TTL, extra_claims={"pwh": fingerprint}
    )
    return token


def _hash_fingerprint(password_hash: str) -> str:
    # A short fingerprint of the password hash, not the hash itself --
    # this claim only needs to detect "has the password changed since
    # this token was issued," not reveal or reproduce the real hash.
    import hashlib

    return hashlib.sha256(password_hash.encode("utf-8")).hexdigest()[:16]


def _decode(secret_key: str, token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError("Token is invalid.") from exc

    if payload.get("type") != expected_type:
        raise TokenError(f"Expected a {expected_type} token.")

    return payload


def decode_access_token(secret_key: str, token: str) -> dict:
    return _decode(secret_key, token, "access")


def decode_refresh_token(secret_key: str, token: str) -> dict:
    return _decode(secret_key, token, "refresh")


def decode_reset_token(secret_key: str, token: str) -> dict:
    return _decode(secret_key, token, "reset")


def reset_token_matches_password_hash(payload: dict, password_hash: str) -> bool:
    return payload.get("pwh") == _hash_fingerprint(password_hash)
