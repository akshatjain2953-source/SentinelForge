"""Tests for the telemetry ingestion endpoint."""
import unittest
from datetime import datetime, timezone
from sentinelforge import create_app


class TelemetryIngestionTestCase(unittest.TestCase):
    """Test cases for POST /api/v1/telemetry."""

    def setUp(self):
        self.app = create_app("testing")
        self.client = self.app.test_client()

    def _valid_payload(self) -> dict:
        """Return a minimal valid telemetry payload."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
            "process": {"name": "cmd.exe", "pid": 1234},
        }

    def test_valid_telemetry_returns_202(self):
        """Test valid telemetry returns 202 Accepted."""
        response = self.client.post(
            "/api/v1/telemetry",
            json=self._valid_payload(),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)
        data = response.get_json()
        self.assertIsNotNone(data)
        self.assertEqual(data.get("status"), "success")
        self.assertIn("message", data)
        self.assertIn("data", data)
        self.assertEqual(data["data"]["event_type"], "process_creation")
        self.assertEqual(data["data"]["source"], "sysmon")

    def test_missing_body_returns_400(self):
        """Test missing request body returns 400."""
        response = self.client.post(
            "/api/v1/telemetry",
            data="",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data.get("status"), "error")
        self.assertEqual(data["error"]["code"], 400)

    def test_malformed_json_returns_400(self):
        """Test malformed JSON returns 400."""
        response = self.client.post(
            "/api/v1/telemetry",
            data="{ invalid json }",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data.get("status"), "error")
        self.assertEqual(data["error"]["code"], 400)

    def test_non_json_content_type_returns_415(self):
        """Test non-JSON content type returns 415."""
        response = self.client.post(
            "/api/v1/telemetry",
            data="timestamp=test&event_type=test&source=test",
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 415)
        data = response.get_json()
        self.assertEqual(data.get("status"), "error")
        self.assertEqual(data["error"]["code"], 415)

    def test_missing_timestamp_returns_422(self):
        """Test missing required timestamp field returns 422."""
        payload = self._valid_payload()
        del payload["timestamp"]
        response = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422)
        data = response.get_json()
        self.assertEqual(data.get("status"), "error")
        self.assertEqual(data["error"]["code"], 422)
        self.assertIn("details", data["error"])
        self.assertTrue(any("timestamp" in d.get("field", "") for d in data["error"]["details"]))

    def test_missing_event_type_returns_422(self):
        """Test missing required event_type field returns 422."""
        payload = self._valid_payload()
        del payload["event_type"]
        response = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422)
        data = response.get_json()
        self.assertEqual(data["error"]["code"], 422)
        self.assertTrue(any("event_type" in d.get("field", "") for d in data["error"]["details"]))

    def test_missing_source_returns_422(self):
        """Test missing required source field returns 422."""
        payload = self._valid_payload()
        del payload["source"]
        response = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422)
        data = response.get_json()
        self.assertEqual(data["error"]["code"], 422)
        self.assertTrue(any("source" in d.get("field", "") for d in data["error"]["details"]))

    def test_empty_event_type_returns_422(self):
        """Test empty event_type returns 422."""
        payload = self._valid_payload()
        payload["event_type"] = ""
        response = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422)
        data = response.get_json()
        self.assertEqual(data["error"]["code"], 422)

    def test_invalid_field_type_returns_422(self):
        """Test invalid field type (e.g., string for pid) returns 422."""
        payload = self._valid_payload()
        payload["process"]["pid"] = "not_an_integer"
        response = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422)
        data = response.get_json()
        self.assertEqual(data["error"]["code"], 422)
        self.assertTrue(any("pid" in d.get("field", "") for d in data["error"]["details"]))

    def test_nested_validation_failure_returns_422(self):
        """Test nested object validation failure returns 422."""
        payload = self._valid_payload()
        payload["file"] = {"size": "not_a_number"}
        response = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422)
        data = response.get_json()
        self.assertEqual(data["error"]["code"], 422)
        self.assertTrue(any("size" in d.get("field", "") for d in data["error"]["details"]))

    def test_minimal_telemetry_accepted(self):
        """Test telemetry with only required fields (no structured fields) is accepted."""
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
        }
        response = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)
        data = response.get_json()
        self.assertEqual(data.get("status"), "success")
        self.assertEqual(data["data"]["event_type"], "process_creation")
        self.assertEqual(data["data"]["source"], "sysmon")

    def test_response_json_structure(self):
        """Test successful response has expected JSON structure."""
        response = self.client.post(
            "/api/v1/telemetry",
            json=self._valid_payload(),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)
        data = response.get_json()

        # Check top-level structure
        self.assertIn("status", data)
        self.assertIn("message", data)
        self.assertIn("data", data)

        # Check data structure
        self.assertIn("event_type", data["data"])
        self.assertIn("source", data["data"])
        self.assertIn("timestamp", data["data"])

        # Check values
        self.assertEqual(data["data"]["event_type"], "process_creation")
        self.assertEqual(data["data"]["source"], "sysmon")

    def test_error_response_no_stack_trace(self):
        """Test error responses do not contain stack traces."""
        response = self.client.post(
            "/api/v1/telemetry",
            json={"timestamp": "invalid", "event_type": "test", "source": "test"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422)
        data = response.get_json()
        response_text = str(data)
        self.assertNotIn("traceback", response_text.lower())
        self.assertNotIn("file ", response_text.lower())
        self.assertNotIn("line ", response_text.lower())

    def test_oversized_request_returns_413(self):
        """Test request exceeding MAX_CONTENT_LENGTH returns 413."""
        # Create a payload larger than 16 MB
        large_raw = {"data": "x" * (17 * 1024 * 1024)}  # ~17 MB
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "test",
            "source": "test",
            "raw": large_raw,
        }
        response = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )
        # Flask returns 413 when MAX_CONTENT_LENGTH is exceeded
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()