"""SentinelForge application package and factory."""
import atexit
import logging
import os
import sys
from typing import Optional
from flask import Flask

from sentinelforge.config import config_by_name, Config
from sentinelforge.logging_config import setup_logging
from sentinelforge.errors import register_error_handlers
from sentinelforge.database import init_db, db
from sentinelforge.detection.cache import RuleCache
from sentinelforge.detection.sync import sync_rules
from sentinelforge.detection.processor import DetectionWorker
from sentinelforge import models  # noqa: F401
from sentinelforge.api.v1 import api_v1_bp

__version__ = "0.1.0"

logger = logging.getLogger(__name__)


def _is_pytest_running() -> bool:
    """Detect if running under pytest."""
    return "pytest" in sys.modules or os.environ.get("PYTEST_CURRENT_TEST") is not None


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

    # Ensure database tables exist for SQLite (testing/development without migrations)
    with app.app_context():
        if app.config.get("SQLALCHEMY_DATABASE_URI", "").startswith("sqlite"):
            db.create_all()

    # Initialize rule cache
    app.extensions["rule_cache"] = RuleCache()

    # Synchronize validated YAML rules to DetectionRule database table
    # Skip during testing to avoid interfering with test isolation
    if not app.config.get("TESTING", False):
        with app.app_context():
            try:
                cache = app.extensions["rule_cache"]
                cache.load()
                validated_rules = cache.get_enabled()
                if validated_rules:
                    sync_rules(validated_rules)
                logger.info("DetectionRule DB sync completed at startup")
            except Exception as e:
                # YAML/cache loading is primary; DB sync is secondary
                # Do not fail startup if DB sync fails
                logger.exception("DetectionRule DB sync failed at startup: %s", e)
    else:
        logger.info("Skipping DetectionRule DB sync during testing")

    # Initialize DetectionWorker (per Flask app instance)
    worker = DetectionWorker(app, app.extensions["rule_cache"])
    app.extensions["detection_worker"] = worker

    # Start worker only in non-testing environments, not under pytest,
    # and only in the reloader child process (or when reloader is disabled).
    # WERKZEUG_RUN_MAIN is "true" in the serving child, "false" in the
    # reloader parent, and unset when reloader is disabled.
    is_pytest = _is_pytest_running()
    is_reloader_child = os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    is_reloader_parent = os.environ.get("WERKZEUG_RUN_MAIN") == "false"
    reloader_disabled = "WERKZEUG_RUN_MAIN" not in os.environ

    should_start_worker = (
        not app.config.get("TESTING", False)
        and not is_pytest
        and (reloader_disabled or is_reloader_child)
        and not is_reloader_parent
    )

    if should_start_worker:
        worker.start()

        # Best-effort shutdown on process exit; register once per app instance
        def _shutdown_worker():
            w = app.extensions.get("detection_worker")
            if w and w.is_running():
                w.stop(timeout=10)

        atexit.register(_shutdown_worker)

    # Register centralized error handlers
    register_error_handlers(app)

    # Register API blueprints
    app.register_blueprint(api_v1_bp)

    return app
