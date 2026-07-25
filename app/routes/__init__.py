from app.routes.admin import admin_bp  # noqa: F401
from app.routes.auth import auth_bp  # noqa: F401
from app.routes.password_reset import password_reset_bp  # noqa: F401


def register_blueprints(app):
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(password_reset_bp, url_prefix="/auth/password-reset")
    app.register_blueprint(admin_bp, url_prefix="/admin")
