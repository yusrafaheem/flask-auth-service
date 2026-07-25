"""Admin-only routes -- the first real consumer of RBAC in this project.

Deliberately minimal (one read-only listing endpoint) since the point of
this file is to demonstrate the roles_required pattern, not to build out
a full admin panel.
"""

from flask import Blueprint, jsonify

from app.models.user import User
from app.security.decorators import auth_required, roles_required

admin_bp = Blueprint("admin", __name__)


@admin_bp.get("/users")
@auth_required
@roles_required("admin")
def list_users():
    users = User.query.order_by(User.created_at).all()
    return (
        jsonify(
            [
                {
                    "id": user.id,
                    "email": user.email,
                    "is_active": user.is_active,
                    "roles": [role.name for role in user.roles],
                }
                for user in users
            ]
        ),
        200,
    )
