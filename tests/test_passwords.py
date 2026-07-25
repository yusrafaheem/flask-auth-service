"""Tests for app.security.passwords.

No Flask app/db needed here -- hashing is pure logic, so these run against
the module directly rather than through the `app` fixture.
"""

from app.security.passwords import hash_password, verify_password


def test_hash_password_returns_different_string_than_input():
    plain = "CorrectHorseBatteryStaple9!"
    hashed = hash_password(plain)

    assert hashed != plain
    assert isinstance(hashed, str)


def test_hash_password_is_salted_so_two_hashes_of_same_password_differ():
    plain = "CorrectHorseBatteryStaple9!"

    assert hash_password(plain) != hash_password(plain)


def test_verify_password_accepts_correct_password():
    plain = "CorrectHorseBatteryStaple9!"
    hashed = hash_password(plain)

    assert verify_password(plain, hashed) is True


def test_verify_password_rejects_wrong_password():
    hashed = hash_password("CorrectHorseBatteryStaple9!")

    assert verify_password("wrong-password", hashed) is False


def test_verify_password_rejects_empty_string():
    hashed = hash_password("CorrectHorseBatteryStaple9!")

    assert verify_password("", hashed) is False


def test_verify_password_handles_malformed_hash_without_raising():
    # A malformed/corrupted hash should fail verification, not blow up the
    # request with an unhandled ValueError.
    assert verify_password("anything", "not-a-real-bcrypt-hash") is False


def test_verify_password_is_case_sensitive():
    hashed = hash_password("CorrectHorseBatteryStaple9!")

    assert verify_password("correcthorsebatterystaple9!", hashed) is False
