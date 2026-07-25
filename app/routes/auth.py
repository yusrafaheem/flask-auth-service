"""Authentication routes.

Starts with just POST /auth/register in this commit; login, refresh,
logout, /me etc. are added in later, separate commits so each endpoint
lands (and can be reviewed) on its own.
"""

from flask import Blueprint, jsonify, request
from marshmallow import ValidationError

from app.extensions import db
from app.models.user import User
from app.schemas.auth_schemas import RegisterSchema
from app.security.password_policy import PasswordPolicyError, validate_password_strength
from app.security.passwords import hash_password

auth_bp = Blueprint("auth", __name__)


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
