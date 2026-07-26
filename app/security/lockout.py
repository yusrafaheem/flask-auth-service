"""Account lockout after repeated failed login attempts.

State lives directly on the User row (failed_login_attempts, locked_until)
-- see app/models/user.py's docstring for why. This module is pure logic
over that state; app/routes/auth.py wires it into the login endpoint in a
separate, later commit so the two concerns (the lockout rule vs. where it
gets called) land independently.
"""

from datetime import datetime, timedelta, timezone

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)


def _as_aware_utc(dt: datetime) -> datetime:
    """SQLite doesn't preserve tzinfo -- `locked_until` comes back naive
    after a round trip through SQLite even though the column is declared
    `DateTime(timezone=True)` (Postgres preserves it correctly). Every
    datetime this app ever writes is already UTC, so treat a naive value
    read back as UTC rather than crashing on the aware/naive comparison
    below.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def is_locked(user) -> bool:
    if user.locked_until is None:
        return False
    return _as_aware_utc(user.locked_until) > datetime.now(timezone.utc)


def register_failed_attempt(user) -> None:
    """Increment the failure counter; lock the account once the threshold
    is hit. Does not commit -- callers are expected to be inside a
    request that will commit the session (e.g. after the login handler
    decides the credentials were wrong).
    """
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + LOCKOUT_DURATION


def register_successful_login(user) -> None:
    """Reset lockout state after a successful login.

    A successful login clears the counter entirely rather than just
    decrementing it -- the failed attempts that preceded a successful
    login are no longer relevant to whether the *next* wrong password
    should start counting toward a fresh lockout.
    """
    user.failed_login_attempts = 0
    user.locked_until = None
