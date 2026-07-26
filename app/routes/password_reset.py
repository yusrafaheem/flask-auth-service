"""Password reset request + confirm endpoints.

No email-sending integration is wired up in this demo-scope project -- a
real deployment would email the reset token/link rather than return it in
the API response. That would leak the reset token to anyone who could
observe the response instead of only the account owner, so it's a
security regression versus a real deployment, not just a missing feature.
See README for this and other tradeoffs made to keep the project runnable
without external services.
"""

from flask import Blueprint, current_app, jsonify, request
from marshmallow import Schema, ValidationError, fields

from app.extensions import db, limiter
from app.models.user import User
from app.security.audit import (
    EVENT_PASSWORD_RESET_CONFIRMED,
    EVENT_PASSWORD_RESET_REQUESTED,
    record_event,
)
from app.security.password_policy import PasswordPolicyError, validate_password_strength
from app.security.passwords import hash_password
from app.security.tokens import TokenError, create_reset_token, decode_reset_token, reset_token_matches_password_hash

password_reset_bp = Blueprint("password_reset", __name__)


class PasswordResetRequestSchema(Schema):
    email = fields.Email(required=True)


class PasswordResetConfirmSchema(Schema):
    token = fields.Str(required=True)
    new_password = fields.Str(required=True)


@password_reset_bp.post("/request")
@limiter.limit("5 per hour")
def request_reset():
    try:
        payload = PasswordResetRequestSchema().load(request.get_json(silent=True) or {})
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400

    email = payload["email"].lower()
    user = User.query.filter_by(email=email).first()

    # Always return the same response whether or not the account exists --
    # otherwise this endpoint becomes an email-enumeration oracle. The
    # actual token (see module docstring) is only ever generated, and only
    # returned in the response, when a matching account does exist.
    response_body = {"message": "If that email is registered, a reset token has been issued."}

    if user is None or not user.is_active:
        return jsonify(response_body), 200

    secret_key = current_app.config["SECRET_KEY"]
    reset_token = create_reset_token(secret_key, user.id, user.password_hash)
    record_event(EVENT_PASSWORD_RESET_REQUESTED, user_id=user.id, email=user.email)
    db.session.commit()

    # Demo-scope only -- see module docstring. A real deployment must not
    # include this field in the HTTP response.
    response_body["reset_token"] = reset_token
    return jsonify(response_body), 200


@password_reset_bp.post("/confirm")
def confirm_reset():
    try:
        payload = PasswordResetConfirmSchema().load(request.get_json(silent=True) or {})
    except ValidationError as err:
        return jsonify({"errors": err.messages}), 400

    secret_key = current_app.config["SECRET_KEY"]
    try:
        token_payload = decode_reset_token(secret_key, payload["token"])
    except TokenError as err:
        return jsonify({"error": str(err)}), 400

    user = User.query.get(token_payload["sub"])
    if user is None:
        return jsonify({"error": "Invalid or expired reset token."}), 400

    if not reset_token_matches_password_hash(token_payload, user.password_hash):
        # Either the password was already changed since this token was
        # issued (via this same reset flow or otherwise), or the token is
        # being replayed after already being used once -- both cases look
        # identical from here, and both must be rejected.
        return jsonify({"error": "Invalid or expired reset token."}), 400

    try:
        validate_password_strength(payload["new_password"])
    except PasswordPolicyError as err:
        return jsonify({"errors": {"new_password": err.errors}}), 400

    user.password_hash = hash_password(payload["new_password"])
    record_event(EVENT_PASSWORD_RESET_CONFIRMED, user_id=user.id, email=user.email)
    db.session.commit()

    return jsonify({"message": "Password has been reset."}), 200
