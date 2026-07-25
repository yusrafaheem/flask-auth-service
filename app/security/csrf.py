"""Double-submit-cookie CSRF protection for cookie-authenticated endpoints.

Only needed once a token lives in a cookie the browser attaches
automatically (the refresh token, since its earlier hardening commit) --
a bearer token in an Authorization header is not automatically attached
to cross-site requests, so it isn't a CSRF target the way a cookie is.

The pattern: on login, a second cookie (readable by JavaScript, unlike
the httpOnly refresh cookie) carries a random CSRF token. The frontend is
expected to read that cookie and echo its value back in an
X-CSRF-Token header on refresh/logout. A cross-site attacker can trick a
victim's browser into *sending* the refresh cookie automatically, but
same-origin policy stops the attacker's page from *reading* the CSRF
cookie to put its value in the header -- so a forged cross-site request
will have a missing or wrong header even though the browser attached the
right cookies.
"""

import hmac
import secrets

from flask import jsonify, request

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_token_is_valid() -> bool:
    cookie_value = request.cookies.get(CSRF_COOKIE_NAME)
    header_value = request.headers.get(CSRF_HEADER_NAME)

    if not cookie_value or not header_value:
        return False

    # Constant-time comparison -- these are compared over a request the
    # same way a secret would be, even though a CSRF token isn't secret
    # from the *legitimate* client (it's readable by same-origin JS by
    # design); it's still not worth leaking via timing to anyone probing
    # the endpoint.
    return hmac.compare_digest(cookie_value, header_value)


def csrf_protect(view):
    """Decorator: reject the request with 403 unless the CSRF cookie and
    X-CSRF-Token header are both present and match.
    """
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not csrf_token_is_valid():
            return jsonify({"error": "Missing or invalid CSRF token."}), 403
        return view(*args, **kwargs)

    return wrapped
