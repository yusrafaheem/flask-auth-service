"""marshmallow schemas for validating auth-related request bodies.

Validation happens here, at the edge, before any handler code touches the
data -- so route handlers can assume `schema.load(...)` already gave them
well-shaped input, instead of every handler re-checking "is email present,
is it a string, is password present" by hand.
"""

from marshmallow import Schema, fields, validate


class RegisterSchema(Schema):
    email = fields.Email(required=True)
    # Password *shape* (min length, presence) is checked here; the deeper
    # strength policy (uppercase/digit/special-char/common-password checks)
    # lives in app.security.password_policy and is applied separately in
    # the route handler, not duplicated into this schema.
    password = fields.Str(required=True, validate=validate.Length(min=1))


class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=1))
