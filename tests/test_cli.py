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

def test_seed_admin_grants_the_role_to_an_existing_user_and_updates_their_password(runner, app):
    with app.app_context():
        from app.models.user import User
        from app.security.passwords import hash_password

        user = User(email="existing@example.com", password_hash=hash_password("OldPassw0rd!"))
        db.session.add(user)
        db.session.commit()

    runner.invoke(
        args=["seed-admin", "--email", "existing@example.com"],
        input=f"{GOOD_PASSWORD}\n{GOOD_PASSWORD}\n",
    )

    with app.app_context():
        from app.models.user import User
        from app.security.passwords import verify_password

        user = User.query.filter_by(email="existing@example.com").first()
        assert user.has_role("admin")
        assert verify_password(GOOD_PASSWORD, user.password_hash)

def test_seed_admin_lowercases_the_email(runner, app):
    runner.invoke(
        args=["seed-admin", "--email", "MixedCase@Example.COM"],
        input=f"{GOOD_PASSWORD}\n{GOOD_PASSWORD}\n",
    )

    with app.app_context():
        from app.models.user import User

        assert User.query.filter_by(email="mixedcase@example.com").first() is not None

def test_seed_admin_rejects_a_weak_password(runner):
    result = runner.invoke(
        args=["seed-admin", "--email", "weak@example.com"],
        input="weak\nweak\n",
    )

    assert result.exit_code == 1
