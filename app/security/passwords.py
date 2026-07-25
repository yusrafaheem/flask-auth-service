"""Password hashing utilities, backed by bcrypt.

bcrypt (not a faster general-purpose hash like SHA-256) is used deliberately:
it is a *slow*, salted, adaptive hash designed for password storage, which
makes brute-force and rainbow-table attacks impractical even if the password
hash table leaks. The work factor (`ROUNDS`) can be raised over time as
hardware gets faster, without changing the verification code -- bcrypt
encodes the cost factor and salt directly in its output string.
"""

import bcrypt

# 12 rounds is bcrypt's common default: strong enough for production while
# still completing in well under a second on typical hardware. Raising this
# trades login latency for brute-force resistance.
ROUNDS = 12


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password for storage.

    Returns a UTF-8 string (bcrypt's own encoded format: algorithm version,
    cost factor, salt, and hash all concatenated) suitable for storing
    directly in the `password_hash` column.
    """
    salt = bcrypt.gensalt(rounds=ROUNDS)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Check a plaintext password against a stored bcrypt hash.

    Uses bcrypt's own comparison (constant-time under the hood) rather than
    `==`, so this doesn't leak timing information about how much of the
    hash matched.
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), password_hash.encode("utf-8")
        )
    except ValueError:
        # Malformed hash (e.g. corrupted data) -- treat as "does not match"
        # rather than raising, so callers don't need a try/except just to
        # check a password.
        return False
