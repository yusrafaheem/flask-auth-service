"""Password strength validation.

This runs *before* hashing, at registration/reset time, so weak passwords
never make it into the database at all -- bcrypt would happily hash
"password123" just as securely as a strong one, but it would still be a
weak password. Policy is deliberately checked as a list of independent
rules with individual messages, rather than one big boolean, so the caller
(and the eventual API response) can tell the user exactly what's wrong.
"""

import re

MIN_LENGTH = 10

# A small, well-known "worst offenders" list rather than an exhaustive
# breach-corpus check (e.g. HaveIBeenPwned's Pwned Passwords API) -- that
# kind of check is a reasonable production upgrade but out of scope here;
# see README for the tradeoff note.
COMMON_PASSWORDS = {
    "password",
    "password1",
    "password123",
    "123456",
    "12345678",
    "qwerty",
    "letmein",
    "admin123",
    "welcome1",
    "iloveyou",
}


class PasswordPolicyError(Exception):
    """Raised with all violated-rule messages when a password fails policy."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def _rule_violations(password: str) -> list[str]:
    errors = []

    if len(password) < MIN_LENGTH:
        errors.append(f"Password must be at least {MIN_LENGTH} characters long.")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain a lowercase letter.")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain an uppercase letter.")

    if not re.search(r"\d", password):
        errors.append("Password must contain a digit.")

    if not re.search(r"[^\w\s]", password):
        errors.append("Password must contain a special character.")

    if password.lower() in COMMON_PASSWORDS:
        errors.append("Password is too common; choose something less guessable.")

    return errors


def validate_password_strength(password: str) -> None:
    """Raise PasswordPolicyError if `password` fails any policy rule.

    Returns None (rather than True/False) on success so the natural calling
    convention is "call it, and if it doesn't raise, the password is fine" --
    which keeps registration/reset handlers from needing an if/else just to
    check strength.
    """
    errors = _rule_violations(password)
    if errors:
        raise PasswordPolicyError(errors)
