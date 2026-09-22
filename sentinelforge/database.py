"""Database extension for SentinelForge."""
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()


def init_db(app):
    """Initialize database extensions with the Flask application."""
    db.init_app(app)
    migrate.init_app(app, db)