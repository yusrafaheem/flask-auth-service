"""Flask CLI commands, registered onto the app in create_app().

`flask init-db` uses `db.create_all()` rather than a migrations tool
(Flask-Migrate/Alembic) -- a deliberate scope simplification for this
project. A real production service should use real migrations so schema
changes are versioned and reversible; `create_all()` only ever adds
missing tables, it never alters an existing one, which is fine for a demo
that always starts from a clean database but would not be fine for a
service with real data to preserve across schema changes.
"""

import click

from app.extensions import db


def register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        """Create all tables that don't already exist."""
        # Imported here, not at module load time, so this module doesn't
        # force-import every model before the app is fully configured.
        from app import models  # noqa: F401

        db.create_all()
        click.echo("Initialized the database.")

    @app.cli.command("seed-admin")
    @click.option("--email", required=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def seed_admin(email, password):
        """Create the 'admin' role (if missing) and an admin user.

        Run manually, once, against a fresh database -- there is no
        signup flow for admin accounts on purpose. Registration via
        POST /auth/register always creates an ordinary, role-less user;
        granting admin has to be a deliberate operator action, not
        something reachable through the public API.
        """
        from app.models.role import Role
        from app.models.user import User
        from app.security.password_policy import PasswordPolicyError, validate_password_strength
        from app.security.passwords import hash_password

        email = email.lower()

        try:
            validate_password_strength(password)
        except PasswordPolicyError as err:
            for message in err.errors:
                click.echo(f"Error: {message}", err=True)
            raise SystemExit(1)

        admin_role = Role.query.filter_by(name="admin").first()
        if admin_role is None:
            admin_role = Role(name="admin")
            db.session.add(admin_role)

        user = User.query.filter_by(email=email).first()
        if user is None:
            user = User(email=email, password_hash=hash_password(password))
            db.session.add(user)
        else:
            user.password_hash = hash_password(password)

        if admin_role not in user.roles:
            user.roles.append(admin_role)

        db.session.commit()
        click.echo(f"Seeded admin user: {email}")
