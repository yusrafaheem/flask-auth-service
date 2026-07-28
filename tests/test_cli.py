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

def test_init_db_is_safe_to_run_twice(runner):
    # create_all() only adds missing tables -- running it again against an
    # already-initialized database (the `app` fixture already called
    # db.create_all() before this test even starts) must not error.
    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0

def test_seed_admin_creates_admin_role_and_user(runner, app):
    result = runner.invoke(
        args=["seed-admin", "--email", "root@example.com"],
        input=f"{GOOD_PASSWORD}\n{GOOD_PASSWORD}\n",
    )

    assert result.exit_code == 0
    with app.app_context():
        from app.models.user import User

        user = User.query.filter_by(email="root@example.com").first()
        assert user is not None
        assert user.has_role("admin")

def test_seed_admin_reuses_the_existing_admin_role_instead_of_duplicating_it(runner, app):
    runner.invoke(
        args=["seed-admin", "--email", "root1@example.com"],
        input=f"{GOOD_PASSWORD}\n{GOOD_PASSWORD}\n",
    )
    runner.invoke(
        args=["seed-admin", "--email", "root2@example.com"],
        input=f"{GOOD_PASSWORD}\n{GOOD_PASSWORD}\n",
    )

    with app.app_context():
        from app.models.role import Role

        # Two seed-admin runs, two different users -- still exactly one
        # "admin" role row, not one per run (see Role.id's default=_uuid
        # fix -- this is the exact code path that bug lived in).
        assert Role.query.filter_by(name="admin").count() == 1
