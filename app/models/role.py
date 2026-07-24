"""RBAC schema: Role plus the User<->Role association table.

A plain many-to-many association table (not its own mapped class) is
enough here because the relationship itself carries no extra data (no
"granted_by" or "granted_at" columns) -- if that ever changes, this would
need to become a real association-object model instead.
"""

from app.extensions import db

user_roles = db.Table(
    "user_roles",
    db.Column("user_id", db.String(36), db.ForeignKey("users.id"), primary_key=True),
    db.Column("role_id", db.String(36), db.ForeignKey("roles.id"), primary_key=True),
)


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    users = db.relationship("User", secondary=user_roles, back_populates="roles")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"<Role {self.name}>"
