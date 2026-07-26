"""Authentication routes.

Endpoints are added incrementally across commits (register, then login,
then /me, then refresh/logout, ...) so each one lands -- and can be
reviewed -- on its own.
"""

from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request
from marshmallow import ValidationError

from app.extensions import db, limiter
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth_schemas import LoginSchema, RegisterSchema
from app.security.audit import (
    EVENT_LOGIN_FAILURE,
    EVENT_LOGIN_LOCKED_OUT,
    EVENT_LOGIN_SUCCESS,
    EVENT_LOGOUT,
    EVENT_REGISTER,
    EVENT_TOKEN_REFRESH,
    record_event,
)
from app.security.csrf import CSRF_COOKIE_NAME, csrf_protect, generate_csrf_token
from app.security.decorators import auth_required
from app.security.lockout import is_locked, register_failed_attempt, register_successful_login
from app.security.password_policy import PasswordPolicyError, validate_password_strength
from app.security.passwords import hash_password, verify_password
from app.security.tokens import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
)

auth_bp = Blueprint("auth", __name__)

# Generic message for any login failure -- wrong password and "no such
# account" both return the exact same response, on purpose. Returning a
# distinct message for "no such user" vs "wrong password" would let an
# attacker enumerate which emails have accounts on this service.
INVALID_CREDENTIALS_MESSAGE = "Invalid email or password."
ACCOUNT_LOCKED_MESSAGE = "Account temporarily locked due to repeated failed login attempts."

# The refresh token now lives in an httpOnly cookie rather than the JSON
# response body -- JavaScript in the browser can no longer read it (so a
# successful XSS attack can't exfiltrate it), and it's automatically
# replayed by the browser only to this cookie's Path, not attached to
# every request the way a global cookie would be.
REFRESH_COOKIE_NAME = "refresh_token"
REFRESH_COOKIE_PATH = "/auth"


def _issue_refresh_token(user_id: str) -> tuple[str, int]:
    """Create a refresh token and persist its DB-backed revocation record.

    Returns (token, ttl_seconds) -- the caller sets the cookie itself,
    since only the caller knows whether it's building a fresh response
    or attaching to one already in progress.

    Shared by /login and /refresh (refresh rotation issues a *new* refresh
    token alongside the new access token) so both call sites stay in sync
    on how a refresh token's lifetime and revocation row get created.
    """
    secret_key = current_app.config["SECRET_KEY"]
    refresh_token, jti = create_refresh_token(secret_key, user_id)

    ttl_seconds = current_app.config["JWT_REFRESH_TOKEN_TTL_SECONDS"]
    expires_at = datetime.now(timezone.utc).timestamp() + ttl_seconds
    db.session.add(
        RefreshToken(
            jti=jti,
            user_id=user_id,
            expires_at=datetime.fromtimestamp(expires_at, tz=timezone.utc),
        )
    )
    return refresh_token, ttl_seconds


def _set_refresh_cookie(response, token: str, max_age: int):
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        token,
        max_age=max_age,
        httponly=True,
        secure=current_app.config["REFRESH_COOKIE_SECURE"],
        samesite="Strict",
        path=REFRESH_COOKIE_PATH,
    )


def _clear_refresh_cookie(response):
    response.delete_cookie(REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH)


def _set_csrf_cookie(response):
    """Set a fresh, JS-readable CSRF token alongside the refresh cookie.

    Deliberately NOT httponly (unlike the refresh cookie) -- the frontend
    must be able to read this value with JavaScript to echo it back in
    the X-CSRF-Token header. See app/security/csrf.py for why that's safe.
    """
    response.set_cookie(
        CSRF_COOKIE_NAME,
        generate_csrf_token(),
        max_age=current_app.config["JWT_REFRESH_TOKEN_TTL_SECONDS"],
        httponly=False,
        secure=current_app.config["REFRESH_COOKIE_SECURE"],
        samesite="Strict",
        path=REFRESH_COOKIE_PATH,
    )


def _clear_csrf_cookie(response):
    response.delete_cookie(CSRF_COOKIE_NAME, path=REFRESH_COOKIE_PATH)


@auth_bp.post("/register")
@limiter.limit("10 per hour")
def register():
    schema = RegisterSchema()
    try:
        payload = schema.load(request.get_json(silent=True) or {})
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400

    email = payload["email"].lower()
    password = payload["password"]

    try:
        validate_password_strength(password)
    except PasswordPolicyError as err:
        return jsonify({"errors": {"password": err.errors}}), 400

    # Checked explicitly (rather than relying solely on the DB unique
    # constraint) so we can return a clean 409 instead of a raw
    # IntegrityError bubbling up as a 500.
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"errors": {"email": ["An account with this email already exists."]}}), 409

    user = User(email=email, password_hash=hash_password(password))
    db.session.add(user)
    db.session.flush()  # assigns user.id so the audit row can reference it
    record_event(EVENT_REGISTER, user_id=user.id, email=user.email)
    db.session.commit()

    return jsonify({"id": user.id, "email": user.email}), 201


@auth_bp.post("/login")
@limiter.limit("10 per minute")
def login():
    schema = LoginSchema()
    try:
        payload = schema.load(request.get_json(silent=True) or {})
    except ValidationError:
        # Deliberately generic here too -- a 400 with schema detail on
        # login would confirm "this field exists," but more importantly
        # we don't want a different response shape for malformed vs wrong
        # credentials, so both paths converge on the same 401 below.
        return jsonify({"error": INVALID_CREDENTIALS_MESSAGE}), 401

    email = payload["email"].lower()
    password = payload["password"]

    user = User.query.filter_by(email=email).first()

    # Checked and returned before the password check (and before it can
    # reset via a correct password) -- once locked, an account stays
    # locked until locked_until passes, full stop.
    if user is not None and is_locked(user):
        record_event(EVENT_LOGIN_LOCKED_OUT, user_id=user.id, email=user.email)
        db.session.commit()
        return jsonify({"error": ACCOUNT_LOCKED_MESSAGE}), 423

    # Always run verify_password, even when no user was found, using a
    # hash-shaped dummy value. bcrypt's check is the slow part of this
    # function; skipping it for unknown emails would make "does this email
    # exist" measurable via response timing.
    dummy_hash = "$2b$12$" + "0" * 53
    password_ok = verify_password(password, user.password_hash if user else dummy_hash)

    if user is None or not password_ok or not user.is_active:
        if user is not None and not password_ok:
            register_failed_attempt(user)
            record_event(EVENT_LOGIN_FAILURE, user_id=user.id, email=user.email)
            db.session.commit()
        else:
            # Either an unknown email, or a correct password against a
            # deactivated account -- either way, still worth an audit
            # row (e.g. for spotting a credential-stuffing sweep), with
            # a user_id attached whenever we do have a matching user.
            record_event(EVENT_LOGIN_FAILURE, user_id=user.id if user else None, email=email)
            db.session.commit()
        return jsonify({"error": INVALID_CREDENTIALS_MESSAGE}), 401

    register_successful_login(user)
    record_event(EVENT_LOGIN_SUCCESS, user_id=user.id, email=user.email)

    secret_key = current_app.config["SECRET_KEY"]
    access_token = create_access_token(secret_key, user.id)
    refresh_token, ttl_seconds = _issue_refresh_token(user.id)
    db.session.commit()

    response = jsonify({"access_token": access_token})
    _set_refresh_cookie(response, refresh_token, ttl_seconds)
    _set_csrf_cookie(response)
    return response, 200


@auth_bp.get("/me")
@auth_required
def me():
    user = g.current_user
    return jsonify({"id": user.id, "email": user.email}), 200


@auth_bp.post("/refresh")
@csrf_protect
def refresh():
    token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not token:
        return jsonify({"error": "Missing refresh token cookie."}), 400

    secret_key = current_app.config["SECRET_KEY"]
    try:
        payload = decode_refresh_token(secret_key, token)
    except TokenError as err:
        return jsonify({"error": str(err)}), 401

    record = RefreshToken.query.filter_by(jti=payload["jti"]).first()
    if record is None or not record.is_active:
        # Covers both "never issued by us" and "already revoked/expired
        # server-side" -- a cryptographically valid JWT whose DB row is
        # gone or revoked must still be rejected; that's the whole point
        # of backing refresh tokens with a DB row instead of trusting the
        # JWT alone.
        return jsonify({"error": "Refresh token has been revoked or is invalid."}), 401

    user = User.query.get(payload["sub"])
    if user is None or not user.is_active:
        return jsonify({"error": "Refresh token has been revoked or is invalid."}), 401

    # Rotate: revoke the presented refresh token and issue a brand new one,
    # rather than reusing it. This limits the blast radius of a leaked
    # refresh token to a single use before it stops working.
    record.revoked_at = datetime.now(timezone.utc)

    access_token = create_access_token(secret_key, user.id)
    new_refresh_token, ttl_seconds = _issue_refresh_token(user.id)
    record_event(EVENT_TOKEN_REFRESH, user_id=user.id, email=user.email)
    db.session.commit()

    response = jsonify({"access_token": access_token})
    _set_refresh_cookie(response, new_refresh_token, ttl_seconds)
    _set_csrf_cookie(response)
    return response, 200


@auth_bp.post("/logout")
@csrf_protect
def logout():
    token = request.cookies.get(REFRESH_COOKIE_NAME)

    response = jsonify({"message": "Logged out."})
    _clear_refresh_cookie(response)
    _clear_csrf_cookie(response)

    if not token:
        return response, 200

    secret_key = current_app.config["SECRET_KEY"]
    try:
        payload = decode_refresh_token(secret_key, token)
    except TokenError:
        # Logout is idempotent from the caller's point of view: an
        # already-invalid token still "successfully" logs out, since the
        # end state (no usable session) is the same either way.
        return response, 200

    record = RefreshToken.query.filter_by(jti=payload["jti"]).first()
    if record is not None and record.revoked_at is None:
        record.revoked_at = datetime.now(timezone.utc)
        record_event(EVENT_LOGOUT, user_id=record.user_id)
        db.session.commit()

    return response, 200
