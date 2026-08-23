"""NetDiag Toolkit Flask application factory."""

from flask import Flask


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)

    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)

    return app
