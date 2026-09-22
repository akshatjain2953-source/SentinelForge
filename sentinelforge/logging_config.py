"""Logging configuration for SentinelForge."""
import logging
import sys
from flask import Flask


def setup_logging(app: Flask) -> None:
    """Configure structured console logging for the Flask application."""
    log_level_name = app.config.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)
    log_format = app.config.get(
        "LOG_FORMAT",
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )

    app.logger.setLevel(log_level)
    app.logger.info(
        f"SentinelForge logging initialized at level: {log_level_name}"
    )
