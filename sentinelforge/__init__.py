"""SentinelForge application package and factory."""
import os
from typing import Optional
from flask import Flask

from sentinelforge.config import config_by_name, Config
from sentinelforge.logging_config import setup_logging
from sentinelforge.errors import register_error_handlers
from sentinelforge.database import init_db
from sentinelforge.detection.cache import RuleCache
from sentinelforge import models  # noqa: F401
from sentinelforge.api.v1 import api_v1_bp

__version__ = "0.1.0"


def create_app(config_name: Optional[str] = None) -> Flask:
    """Application factory for SentinelForge Flask REST API."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "development")

    app = Flask(__name__)

    # Load configuration
    config_class = config_by_name.get(config_name, Config)
    app.config.from_object(config_class)
    app.config["ENV"] = config_name
    config_class.init_app(app)

    # Setup Logging
    setup_logging(app)

    # Initialize database
    init_db(app)

    # Initialize rule cache
    app.extensions["rule_cache"] = RuleCache()

    # Register centralized error handlers
    register_error_handlers(app)

    # Register API blueprints
    app.register_blueprint(api_v1_bp)

    return app
