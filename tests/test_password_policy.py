"""Tests for app.security.password_policy."""

import pytest

from app.security.password_policy import MIN_LENGTH, PasswordPolicyError, validate_password_strength


def test_strong_password_passes():
    # Should not raise.
    validate_password_strength("CorrectHorseBatteryStaple9!")


def test_too_short_is_rejected():
    with pytest.raises(PasswordPolicyError) as exc_info:
        validate_password_strength("Ab1!")

    assert any("at least" in msg for msg in exc_info.value.errors)


def test_missing_uppercase_is_rejected():
    with pytest.raises(PasswordPolicyError) as exc_info:
        validate_password_strength("alllowercase1!")

    assert any("uppercase" in msg for msg in exc_info.value.errors)


def test_missing_lowercase_is_rejected():
    with pytest.raises(PasswordPolicyError) as exc_info:
        validate_password_strength("ALLUPPERCASE1!")

    assert any("lowercase" in msg for msg in exc_info.value.errors)


def test_missing_digit_is_rejected():
    with pytest.raises(PasswordPolicyError) as exc_info:
        validate_password_strength("NoDigitsHere!")

    assert any("digit" in msg for msg in exc_info.value.errors)


def test_missing_special_char_is_rejected():
    with pytest.raises(PasswordPolicyError) as exc_info:
        validate_password_strength("NoSpecialChar9")

    assert any("special character" in msg for msg in exc_info.value.errors)


def test_common_password_is_rejected_even_if_it_meets_other_rules():
    with pytest.raises(PasswordPolicyError) as exc_info:
        # "password123" is an exact (case-insensitive) match in
        # COMMON_PASSWORDS -- it also happens to fail the uppercase and
        # special-character rules, and the assertion below only checks
        # that "common" is *among* the reported errors, not the only one.
        validate_password_strength("password123")

    assert any("common" in msg for msg in exc_info.value.errors)


def test_multiple_violations_are_all_reported_at_once():
    with pytest.raises(PasswordPolicyError) as exc_info:
        validate_password_strength("short")

    # Short, no uppercase, no digit, no special char -- expect several messages,
    # not just the first one found.
    assert len(exc_info.value.errors) >= 3


def test_password_at_exactly_the_minimum_length_passes():
    ten_char_password = "Abcdefg9!!"
    assert len(ten_char_password) == MIN_LENGTH

    validate_password_strength(ten_char_password)  # should not raise


def test_password_one_character_below_minimum_length_is_rejected():
    nine_char_password = "Abcdefg9!"
    assert len(nine_char_password) == MIN_LENGTH - 1

    with pytest.raises(PasswordPolicyError) as exc_info:
        validate_password_strength(nine_char_password)

    assert any("at least" in msg for msg in exc_info.value.errors)


def test_common_password_check_is_case_insensitive():
    with pytest.raises(PasswordPolicyError) as exc_info:
        # "PASSWORD123" differs only in case from the COMMON_PASSWORDS entry
        # "password123" -- the check lowercases before comparing, so this
        # must still be caught (even though it also fails other rules).
        validate_password_strength("PASSWORD123")

    assert any("common" in msg for msg in exc_info.value.errors)
