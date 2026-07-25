"""Route decorators for authentication (and, later, authorization).

`auth_required` is the only thing here for now; `roles_required` (RBAC)
is added in a later, separate commit once the role model is wired up to
routes.
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
