"""Tests for centralized error handlers."""
import unittest
from sentinelforge import create_app


class ErrorHandlersTestCase(unittest.TestCase):
    """Test error handler behavior and JSON output."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def test_404_not_found(self):
        """Verify 404 returns structured JSON error."""
        response = self.client.get("/api/v1/nonexistent-route")
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertIsNotNone(data)
        self.assertEqual(data.get("status"), "error")
        self.assertEqual(data["error"]["code"], 404)
        self.assertIn("message", data["error"])

    def test_405_method_not_allowed(self):
        """Verify 405 returns structured JSON error."""
        response = self.client.post("/api/v1/health")
        self.assertEqual(response.status_code, 405)
        data = response.get_json()
        self.assertIsNotNone(data)
        self.assertEqual(data.get("status"), "error")
        self.assertEqual(data["error"]["code"], 405)


if __name__ == "__main__":
    unittest.main()
