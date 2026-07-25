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


def is_locked(user) -> bool:
    return user.locked_until is not None and user.locked_until > datetime.now(timezone.utc)


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
