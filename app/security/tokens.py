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

ALGORITHM = "HS256"


class TokenError(Exception):
    """Raised for any invalid, expired, tampered, or wrong-type token."""


def _encode(secret_key: str, user_id: int, token_type: str, ttl: timedelta) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "iat": now,
        "exp": now + ttl,
        "jti": jti,
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
