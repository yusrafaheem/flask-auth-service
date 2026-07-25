"""Shared pytest fixtures.

`app` builds a fresh Flask app per test using TestingConfig (in-memory
SQLite, rate limiting disabled) via the app factory -- this is the whole
reason create_app() takes a config_name instead of building a module-level
app object. Each test gets its own tables via db.create_all()/drop_all(),
so tests can't leak state into each other through a shared database file.
"""

import pytest

from app import create_app
from app.extensions import db


@pytest.fixture()
def app():
    application = create_app("testing")

    with application.app_context():
        from app import models  # noqa: F401

        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()
