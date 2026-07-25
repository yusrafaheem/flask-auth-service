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
