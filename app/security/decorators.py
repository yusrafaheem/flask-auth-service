"""Route decorators for authentication and role-based authorization.

`roles_required` must be stacked *below* `auth_required` (i.e. closer to
the view function) since it reads `g.current_user`, which `auth_required`
is what sets. Stacked the other way around, `g.current_user` wouldn't
exist yet when `roles_required` runs.
"""

from functools import wraps

from flask import current_app, g, jsonify, request

from app.models.user import User
from app.security.tokens import TokenError, decode_access_token


def _extract_bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header[len("Bearer ") :].strip() or None


def auth_required(view):
    """Require a valid access-token Bearer header; attach the user to `g`.

    Sets `g.current_user` rather than passing the user as a positional
    argument, so decorated view functions keep their normal Flask
    signature (no extra parameter every route has to declare) -- routes
    that need the user just read `g.current_user`.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        token = _extract_bearer_token()
        if token is None:
            return jsonify({"error": "Missing or malformed Authorization header."}), 401

        try:
            payload = decode_access_token(current_app.config["SECRET_KEY"], token)
        except TokenError as err:
            return jsonify({"error": str(err)}), 401

        user = User.query.get(payload["sub"])
        if user is None or not user.is_active:
            # Covers the case where a token was issued for a user who was
            # later deleted or deactivated -- the token can still verify
            # cryptographically, but the account it points to no longer
            # exists or is disabled, so the request must still be denied.
            return jsonify({"error": "Invalid or expired token."}), 401

        g.current_user = user
        return view(*args, **kwargs)

    return wrapped


def roles_required(*role_names: str):
    """Require the authenticated user to have at least one of the given
    roles. Must be used together with (and beneath) @auth_required, since
    it relies on g.current_user already being set.
    """

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = g.current_user
            if not any(user.has_role(name) for name in role_names):
                return jsonify({"error": "Forbidden: insufficient role."}), 403
            return view(*args, **kwargs)

        return wrapped

    return decorator
