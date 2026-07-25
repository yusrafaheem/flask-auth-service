from app.routes.auth import auth_bp  # noqa: F401


def register_blueprints(app):
    app.register_blueprint(auth_bp, url_prefix="/auth")
