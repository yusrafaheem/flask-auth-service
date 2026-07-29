"""Tests for app.schemas.auth_schemas."""

import pytest
from marshmallow import ValidationError

from app.schemas.auth_schemas import LoginSchema, RegisterSchema


def test_register_schema_accepts_valid_payload():
    data = RegisterSchema().load({"email": "user@example.com", "password": "whatever"})

    assert data["email"] == "user@example.com"
    assert data["password"] == "whatever"


def test_register_schema_rejects_invalid_email():
    with pytest.raises(ValidationError) as exc_info:
        RegisterSchema().load({"email": "not-an-email", "password": "whatever"})

    assert "email" in exc_info.value.messages


def test_register_schema_rejects_missing_password():
    with pytest.raises(ValidationError) as exc_info:
        RegisterSchema().load({"email": "user@example.com"})

    assert "password" in exc_info.value.messages


def test_register_schema_rejects_empty_password():
    with pytest.raises(ValidationError) as exc_info:
        RegisterSchema().load({"email": "user@example.com", "password": ""})

    assert "password" in exc_info.value.messages


def test_login_schema_accepts_valid_payload():
    data = LoginSchema().load({"email": "user@example.com", "password": "whatever"})

    assert data["email"] == "user@example.com"


def test_login_schema_rejects_missing_email():
    with pytest.raises(ValidationError) as exc_info:
        LoginSchema().load({"password": "whatever"})

    assert "email" in exc_info.value.messages


def test_register_schema_rejects_missing_email():
    with pytest.raises(ValidationError) as exc_info:
        RegisterSchema().load({"password": "whatever"})

    assert "email" in exc_info.value.messages


def test_login_schema_rejects_missing_password():
    with pytest.raises(ValidationError) as exc_info:
        LoginSchema().load({"email": "user@example.com"})

    assert "password" in exc_info.value.messages


def test_login_schema_rejects_invalid_email():
    with pytest.raises(ValidationError) as exc_info:
        LoginSchema().load({"email": "not-an-email", "password": "whatever"})

    assert "email" in exc_info.value.messages


def test_login_schema_rejects_empty_password():
    with pytest.raises(ValidationError) as exc_info:
        LoginSchema().load({"email": "user@example.com", "password": ""})

    assert "password" in exc_info.value.messages


def test_register_schema_rejects_unknown_fields():
    # marshmallow's default unknown-field policy is RAISE -- a stray field
    # (e.g. a client accidentally sending "is_admin": true) must fail
    # validation rather than being silently dropped or accepted.
    with pytest.raises(ValidationError) as exc_info:
        RegisterSchema().load(
            {"email": "user@example.com", "password": "whatever", "is_admin": True}
        )

    assert "is_admin" in exc_info.value.messages
