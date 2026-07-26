"""Structured audit logging for security-relevant events.

`record_event` only *adds* the AuditLog row to the session -- it
deliberately does not call db.session.commit() itself. Every call site
in this codebase is already about to commit its own transaction (e.g.
login committing the lockout-counter update, or register committing the
new User row), so committing here too would just be a second round trip
for no benefit. If a call site's transaction rolls back, the audit
record rolls back with it -- which is correct: we don't want an audit
log entry for a registration that didn't actually happen because the DB
write failed.
"""

from typing import Optional

from flask import request

from app.extensions import db
from app.models.audit_log import AuditLog

# Central list of event_type strings so call sites can't typo a value
# that never gets queried for later. Not enforced at the DB layer (the
# column is a plain string) -- this is a convention, not a constraint,
# to keep AuditLog usable for event types this file's author didn't
# anticipate.
EVENT_REGISTER = "register"
EVENT_LOGIN_SUCCESS = "login_success"
EVENT_LOGIN_FAILURE = "login_failure"
EVENT_LOGIN_LOCKED_OUT = "login_locked_out"
EVENT_LOGOUT = "logout"
EVENT_TOKEN_REFRESH = "token_refresh"
EVENT_PASSWORD_RESET_REQUESTED = "password_reset_requested"
EVENT_PASSWORD_RESET_CONFIRMED = "password_reset_confirmed"


def record_event(
    event_type: str,
    user_id: Optional[str] = None,
    email: Optional[str] = None,
    detail: Optional[str] = None,
) -> AuditLog:
    """Stage an AuditLog row for the current request.

    ip_address is read from request.remote_addr here, once, rather than
    asking every call site to pass it -- so a future auth event nobody's
    written yet still gets IP capture for free just by calling this
    function.
    """
    entry = AuditLog(
        event_type=event_type,
        user_id=user_id,
        email_at_time=email,
        ip_address=request.remote_addr if request else None,
        detail=detail,
    )
    db.session.add(entry)
    return entry
