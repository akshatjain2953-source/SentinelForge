"""Tests for the health check endpoint."""
import unittest
from sentinelforge import create_app


class HealthEndpointTestCase(unittest.TestCase):
    """Test cases for GET /api/v1/health."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_health_check_status_code(self):
        """Ensure GET /api/v1/health returns HTTP 200."""
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)

    def test_health_check_payload(self):
        """Ensure GET /api/v1/health returns valid JSON with expected keys."""
        response = self.client.get("/api/v1/health")
        data = response.get_json()

        self.assertIsNotNone(data)
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("service"), "sentinelforge-api")
        self.assertEqual(data.get("version"), "v1")
        self.assertEqual(data.get("environment"), "testing")


if __name__ == "__main__":
    unittest.main()
