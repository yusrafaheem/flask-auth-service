"""Authentication routes.

Endpoints are added incrementally across commits (register, then login,
then /me, then refresh/logout, ...) so each one lands -- and can be
reviewed -- on its own.
"""

from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request
from marshmallow import ValidationError

from app.extensions import db
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.schemas.auth_schemas import LoginSchema, RegisterSchema
from app.security.decorators import auth_required
from app.security.password_policy import PasswordPolicyError, validate_password_strength
from app.security.passwords import hash_password, verify_password
from app.security.tokens import create_access_token, create_refresh_token

auth_bp = Blueprint("auth", __name__)

# Generic message for any login failure -- wrong password and "no such
# account" both return the exact same response, on purpose. Returning a
# distinct message for "no such user" vs "wrong password" would let an
# attacker enumerate which emails have accounts on this service.
INVALID_CREDENTIALS_MESSAGE = "Invalid email or password."


@auth_bp.post("/register")
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
    db.session.commit()

    return jsonify({"id": user.id, "email": user.email}), 201


@auth_bp.post("/login")
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

    # Always run verify_password, even when no user was found, using a
    # hash-shaped dummy value. bcrypt's check is the slow part of this
    # function; skipping it for unknown emails would make "does this email
    # exist" measurable via response timing.
    dummy_hash = "$2b$12$" + "0" * 53
    password_ok = verify_password(password, user.password_hash if user else dummy_hash)

    if user is None or not password_ok or not user.is_active:
        return jsonify({"error": INVALID_CREDENTIALS_MESSAGE}), 401

    secret_key = current_app.config["SECRET_KEY"]
    access_token = create_access_token(secret_key, user.id)
    refresh_token, jti = create_refresh_token(secret_key, user.id)

    ttl_seconds = current_app.config["JWT_REFRESH_TOKEN_TTL_SECONDS"]
    expires_at = datetime.now(timezone.utc).timestamp() + ttl_seconds
    db.session.add(
        RefreshToken(
            jti=jti,
            user_id=user.id,
            expires_at=datetime.fromtimestamp(expires_at, tz=timezone.utc),
        )
    )
    db.session.commit()

    return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200


@auth_bp.get("/me")
@auth_required
def me():
    user = g.current_user
    return jsonify({"id": user.id, "email": user.email}), 200
