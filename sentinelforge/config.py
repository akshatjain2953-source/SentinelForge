"""SentinelForge configuration management via environment variables."""
import os
from typing import Dict, Type


class Config:
    """Base configuration with safe defaults."""

    # Flask Core
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-insecure-secret-key-change-in-production")
    DEBUG: bool = False
    TESTING: bool = False

    # API Metadata
    API_TITLE: str = os.environ.get("API_TITLE", "SentinelForge API")
    API_VERSION: str = "v1"
    SERVICE_NAME: str = "sentinelforge-api"

    # Security & Error Handling
    PROPAGATE_EXCEPTIONS: bool = False

    # Logging
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Database
    SQLALCHEMY_DATABASE_URI: str = os.environ.get("DATABASE_URL", "postgresql://localhost/sentinelforge")
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ECHO: bool = False

    @classmethod
    def init_app(cls, app):
        """Hook for initializing configuration on the Flask app."""
        pass


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG: bool = True
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "DEBUG")
    SQLALCHEMY_ECHO: bool = os.environ.get("SQLALCHEMY_ECHO", "False").lower() == "true"


class TestingConfig(Config):
    """Testing configuration."""

    TESTING: bool = True
    DEBUG: bool = False
    LOG_LEVEL: str = "WARNING"
    SECRET_KEY: str = "test-secret-key"
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    SQLALCHEMY_ECHO: bool = False


class ProductionConfig(Config):
    """Production configuration with strict validation."""

    DEBUG: bool = False
    TESTING: bool = False
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")
    SQLALCHEMY_ECHO: bool = False

    @classmethod
    def init_app(cls, app):
        super().init_app(app)
        # Ensure production secret key is explicitly set and not using default
        secret = os.environ.get("SECRET_KEY")
        if not secret or secret == "dev-insecure-secret-key-change-in-production":
            raise ValueError("SECRET_KEY environment variable must be set securely in production.")
        # Ensure production database URL is explicitly set
        db_url = os.environ.get("DATABASE_URL")
        if not db_url or db_url == "postgresql://localhost/sentinelforge":
            raise ValueError("DATABASE_URL environment variable must be set securely in production.")


config_by_name: Dict[str, Type[Config]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
