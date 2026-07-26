"""RBAC schema: Role plus the User<->Role association table.

A plain many-to-many association table (not its own mapped class) is
enough here because the relationship itself carries no extra data (no
"granted_by" or "granted_at" columns) -- if that ever changes, this would
need to become a real association-object model instead.
"""

import uuid

from app.extensions import db

user_roles = db.Table(
    "user_roles",
    db.Column("user_id", db.String(36), db.ForeignKey("users.id"), primary_key=True),
    db.Column("role_id", db.String(36), db.ForeignKey("roles.id"), primary_key=True),
)


def _uuid() -> str:
    return str(uuid.uuid4())


class Role(db.Model):
    __tablename__ = "roles"

    # `default=_uuid` was missing here -- every other model's String(36)
    # primary key generates its own id (see User, RefreshToken,
    # AuditLog), but this one didn't, so creating a Role without
    # explicitly passing an id hit SQLite's NOT NULL constraint on
    # roles.id. That includes `flask seed-admin` (app/cli.py), which
    # also creates a bare `Role(name=...)` -- this was a real bug in
    # both paths, only caught here because test_rbac.py was the first
    # thing to actually exercise Role creation end-to-end.
    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    name = db.Column(db.String(50), unique=True, nullable=False)

    users = db.relationship("User", secondary=user_roles, back_populates="roles")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"<Role {self.name}>"
