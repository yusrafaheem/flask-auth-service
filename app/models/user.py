"""The User model.

Lockout fields (failed_login_attempts, locked_until) live directly on the
user row rather than in a separate table -- there's exactly one active
lockout state per user at a time, so a join buys nothing here. See
app/security/lockout.py (added later in this repo's history) for the
logic that reads and writes these fields.
"""

import uuid
from datetime import datetime, timezone

from app.extensions import db


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    is_active = db.Column(db.Boolean, nullable=False, default=True)

    # Account lockout state -- see app/security/lockout.py.
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    # Populated via app.models.role.user_roles; imported lazily inside the
    # relationship string form so app/models/user.py doesn't need to import
    # app/models/role.py directly (avoids a circular import between the two
    # model modules, since role.py's Role.users relationship points back
    # here).
    roles = db.relationship("Role", secondary="user_roles", back_populates="users")

    def has_role(self, role_name: str) -> bool:
        return any(role.name == role_name for role in self.roles)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"<User {self.email}>"
