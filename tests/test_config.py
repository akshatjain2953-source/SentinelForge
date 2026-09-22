"""Tests for configuration loading and validation."""
import unittest
from sentinelforge import create_app
from sentinelforge.config import ProductionConfig
from sentinelforge.database import db


class ConfigTestCase(unittest.TestCase):
    """Test configuration behavior across environments."""

    def test_development_config(self):
        """Verify development configuration properties."""
        app = create_app("development")
        self.assertTrue(app.config["DEBUG"])
        self.assertFalse(app.config["TESTING"])
        self.assertEqual(app.config["SQLALCHEMY_DATABASE_URI"], "postgresql://localhost/sentinelforge")
        self.assertFalse(app.config["SQLALCHEMY_TRACK_MODIFICATIONS"])

    def test_testing_config(self):
        """Verify testing configuration properties."""
        app = create_app("testing")
        self.assertFalse(app.config["DEBUG"])
        self.assertTrue(app.config["TESTING"])
        self.assertEqual(app.config["SQLALCHEMY_DATABASE_URI"], "sqlite:///:memory:")

    def test_production_config_rejects_insecure_default_secret(self):
        """Verify production rejects default insecure secret key."""
        app = create_app("testing")
        with self.assertRaises(ValueError):
            # Attempt to init app with default insecure secret in production mode
            ProductionConfig.init_app(app)

    def test_production_config_rejects_default_database_url(self):
        """Verify production rejects default insecure database URL."""
        app = create_app("testing")
        with self.assertRaises(ValueError):
            ProductionConfig.init_app(app)


class DatabaseInitTestCase(unittest.TestCase):
    """Test database extension initialization."""

    def test_database_extension_initialized(self):
        """Verify SQLAlchemy extension is initialized with the app."""
        app = create_app("testing")
        with app.app_context():
            self.assertIsNotNone(db.engine)
            # Testing config uses in-memory SQLite
            self.assertIn("sqlite", str(db.engine.url))

    def test_database_tables_can_be_created(self):
        """Verify database tables can be created with models."""
        app = create_app("testing")
        with app.app_context():
            db.create_all()
            # Should not raise - tables created successfully
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            expected_tables = {
                "users",
                "roles",
                "user_roles",
                "telemetry_events",
                "detection_rules",
                "detection_executions",
                "alerts",
                "incidents",
                "attck_techniques",
                "alert_attck",
                "audit_logs",
                "telemetry_quarantine",
            }
            self.assertEqual(set(tables), expected_tables)


if __name__ == "__main__":
    unittest.main()
