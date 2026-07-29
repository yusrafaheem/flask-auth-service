"""Tests for RBAC (roles_required), exercised through GET /admin/users."""

from app.security.passwords import hash_password
from app.security.tokens import create_access_token


def _make_user(app, email, password="CorrectHorseBatteryStaple9!", roles=()):
    with app.app_context():
        from app.extensions import db
        from app.models.role import Role
        from app.models.user import User

        user = User(email=email, password_hash=hash_password(password))
        for role_name in roles:
            role = Role.query.filter_by(name=role_name).first()
            if role is None:
                role = Role(name=role_name)
                db.session.add(role)
            user.roles.append(role)
        db.session.add(user)
        db.session.commit()
        return user.id


def _token_for(app, user_id):
    with app.app_context():
        return create_access_token(app.config["SECRET_KEY"], user_id)


def test_admin_endpoint_rejects_unauthenticated_requests(client):
    resp = client.get("/admin/users")

    assert resp.status_code == 401


def test_admin_endpoint_forbids_a_regular_user(client, app):
    user_id = _make_user(app, "regular@example.com", roles=())
    token = _token_for(app, user_id)

    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 403


def test_admin_endpoint_allows_an_admin_user(client, app):
    user_id = _make_user(app, "admin@example.com", roles=("admin",))
    token = _token_for(app, user_id)

    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)


def test_admin_endpoint_response_includes_role_names(client, app):
    user_id = _make_user(app, "admin2@example.com", roles=("admin",))
    token = _token_for(app, user_id)

    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    body = resp.get_json()
    admin_entry = next(u for u in body if u["email"] == "admin2@example.com")
    assert "admin" in admin_entry["roles"]


def test_admin_endpoint_does_not_leak_password_hashes(client, app):
    _make_user(app, "admin3@example.com", roles=("admin",))
    user_id = _make_user(app, "admin4@example.com", roles=("admin",))
    token = _token_for(app, user_id)

    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    body_text = resp.get_data(as_text=True)
    assert "password_hash" not in body_text
    assert "$2b$" not in body_text  # bcrypt hash prefix must never appear


def test_admin_endpoint_rejects_wrong_http_method(client, app):
    user_id = _make_user(app, "admin5@example.com", roles=("admin",))
    token = _token_for(app, user_id)

    resp = client.post("/admin/users", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 405


def test_admin_endpoint_lists_users_in_creation_order(client, app):
    _make_user(app, "first-created@example.com", roles=())
    user_id = _make_user(app, "second-created@example.com", roles=("admin",))
    token = _token_for(app, user_id)

    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    emails = [u["email"] for u in resp.get_json()]
    assert emails.index("first-created@example.com") < emails.index("second-created@example.com")
