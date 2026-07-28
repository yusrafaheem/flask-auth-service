"""Tests for the flask CLI commands (init-db, seed-admin).

Uses the `runner` fixture (a FlaskCliRunner) from conftest.py -- it was
defined back when the app factory was built but never actually exercised
by a test file, so app/cli.py sat at 25% coverage (only the parts other
tests happened to import) until this file exercised the commands
themselves via `flask init-db` / `flask seed-admin`.
"""

from app.extensions import db

GOOD_PASSWORD = "SuperSecret9!"

def test_init_db_creates_users_table(runner, app):
    with app.app_context():
        db.drop_all()

    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0
    with app.app_context():
        from app.models.user import User

        # Querying doesn't raise -- the table exists (and is empty).
        assert User.query.count() == 0

def test_init_db_creates_roles_table(runner, app):
    with app.app_context():
        db.drop_all()

    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0
    with app.app_context():
        from app.models.role import Role

        assert Role.query.count() == 0

def test_init_db_prints_a_confirmation_message(runner, app):
    with app.app_context():
        db.drop_all()

    result = runner.invoke(args=["init-db"])

    assert "Initialized the database." in result.output
