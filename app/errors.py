"""Generic, enumeration-resistant error handlers.

Flask's default error pages (and an unhandled exception's default 500)
either leak implementation detail -- a stack trace, a library name, a
SQL fragment in a debug traceback -- or return HTML when every other
response from this API is JSON. Both are a problem for a service whose
whole purpose is to be hard to probe: an attacker fingerprinting this
app for known-vulnerable dependency versions, or triggering a 500 to
see what leaks, gets nothing usable from either. Also normalizes shape
(every error path becomes {"error": "..."}) so client code doesn't have
to special-case Flask's own default-error-page HTML anywhere.
"""

import logging

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(HTTPException)
    def handle_http_exception(err: HTTPException):
        # Covers every standard HTTP error Flask/Werkzeug can raise --
        # 404, 405, 413, etc. -- with one generic, JSON-shaped body per
        # status code, instead of Werkzeug's default HTML error page.
        # err.code / err.name are Werkzeug's own generic strings (e.g.
        # "Not Found"), not anything from this app's internals, so
        # they're safe to return as-is.
        return jsonify({"error": err.name}), err.code

    @app.errorhandler(Exception)
    def handle_unexpected_exception(err: Exception):
        # Anything that isn't an intentional HTTPException is a bug --
        # log the real exception server-side for debugging, but never
        # put its message, type, or traceback in the response. A raw
        # exception message can contain table/column names, file paths,
        # or library versions that make an attacker's job easier.
        logger.exception("Unhandled exception while processing request")
        return jsonify({"error": "Internal Server Error"}), 500
