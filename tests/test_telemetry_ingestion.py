"""Tests for the telemetry ingestion endpoint."""
import unittest
from datetime import datetime, timezone
from sentinelforge import create_app
from sentinelforge.database import db


class TelemetryIngestionTestCase(unittest.TestCase):
    """Test cases for POST /api/v1/telemetry."""

    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

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


class TelemetryPersistenceTestCase(unittest.TestCase):
    """Test cases for telemetry persistence to database."""

    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_valid_telemetry_creates_telemetry_event(self):
        """Test valid telemetry creates a TelemetryEvent record."""
        from sentinelforge.models import TelemetryEvent

        payload = self._valid_payload()
        response = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)

        # Verify the event was persisted
        events = TelemetryEvent.query.all()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsNotNone(event.id)

    def test_stored_source_is_correct(self):
        """Test stored source matches the input."""
        from sentinelforge.models import TelemetryEvent

        payload = self._valid_payload()
        payload["source"] = "custom_source"
        self.client.post("/api/v1/telemetry", json=payload, content_type="application/json")

        event = TelemetryEvent.query.first()
        self.assertEqual(event.source, "custom_source")

    def test_stored_event_type_is_correct(self):
        """Test stored event_type matches the input."""
        from sentinelforge.models import TelemetryEvent

        payload = self._valid_payload()
        payload["event_type"] = "custom_event_type"
        self.client.post("/api/v1/telemetry", json=payload, content_type="application/json")

        event = TelemetryEvent.query.first()
        self.assertEqual(event.event_type, "custom_event_type")

    def test_event_timestamp_preserved(self):
        """Test event timestamp from payload is preserved in stored payload."""
        from sentinelforge.models import TelemetryEvent

        test_timestamp = "2026-01-15T10:30:45+00:00"
        payload = self._valid_payload()
        payload["timestamp"] = test_timestamp
        self.client.post("/api/v1/telemetry", json=payload, content_type="application/json")

        event = TelemetryEvent.query.first()
        self.assertEqual(event.payload["timestamp"], test_timestamp)

    def test_received_at_is_server_generated(self):
        """Test received_at is generated server-side, not from client."""
        from sentinelforge.models import TelemetryEvent

        self.client.post("/api/v1/telemetry", json=self._valid_payload(), content_type="application/json")

        event = TelemetryEvent.query.first()
        self.assertIsNotNone(event.received_at)
        # received_at should be close to now (within a few seconds)
        # Ensure both datetimes are timezone-aware for comparison
        now = datetime.now(timezone.utc)
        received = event.received_at
        if received.tzinfo is None:
            received = received.replace(tzinfo=timezone.utc)
        diff = abs((now - received).total_seconds())
        self.assertLess(diff, 5)  # within 5 seconds

    def test_structured_fields_preserved(self):
        """Test all structured fields are preserved in payload."""
        from sentinelforge.models import TelemetryEvent

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "network_connection",
            "source": "sysmon",
            "host": {"hostname": "DESKTOP-01", "ip": "192.168.1.10"},
            "user": {"name": "admin", "domain": "CORP"},
            "process": {"name": "chrome.exe", "pid": 5678, "command_line": "chrome.exe --test"},
            "network": {"protocol": "tcp", "dst_ip": "8.8.8.8", "dst_port": 443},
            "file": {"path": "C:\\temp\\file.txt", "size": 1024},
            "metadata": {"collector": "sysmon", "version": "8.0"},
        }
        self.client.post("/api/v1/telemetry", json=payload, content_type="application/json")

        event = TelemetryEvent.query.first()
        self.assertEqual(event.payload["host"]["hostname"], "DESKTOP-01")
        self.assertEqual(event.payload["user"]["name"], "admin")
        self.assertEqual(event.payload["process"]["pid"], 5678)
        self.assertEqual(event.payload["network"]["dst_port"], 443)
        self.assertEqual(event.payload["file"]["size"], 1024)
        self.assertEqual(event.payload["metadata"]["collector"], "sysmon")

    def test_metadata_raw_preserved(self):
        """Test metadata and raw fields are preserved."""
        from sentinelforge.models import TelemetryEvent

        payload = self._valid_payload()
        payload["metadata"] = {"collector": "test", "correlation_id": "550e8400-e29b-41d4-a716-446655440000"}
        payload["raw"] = {"custom_field": "custom_value", "number": 42}
        self.client.post("/api/v1/telemetry", json=payload, content_type="application/json")

        event = TelemetryEvent.query.first()
        self.assertEqual(event.payload["metadata"]["collector"], "test")
        self.assertEqual(event.payload["metadata"]["correlation_id"], "550e8400-e29b-41d4-a716-446655440000")
        self.assertEqual(event.payload["raw"]["custom_field"], "custom_value")

    def test_minimal_telemetry_persists_successfully(self):
        """Test minimal telemetry (only required fields) persists successfully."""
        from sentinelforge.models import TelemetryEvent

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "heartbeat",
            "source": "windows",
        }
        response = self.client.post("/api/v1/telemetry", json=payload, content_type="application/json")
        self.assertEqual(response.status_code, 202)

        event = TelemetryEvent.query.first()
        self.assertIsNotNone(event)
        self.assertEqual(event.source, "windows")
        self.assertEqual(event.event_type, "heartbeat")
        self.assertIn("timestamp", event.payload)

    def test_invalid_telemetry_never_reaches_database(self):
        """Test invalid telemetry never creates a database record."""
        from sentinelforge.models import TelemetryEvent

        # Missing required field
        payload = {"event_type": "test", "source": "test"}  # no timestamp
        response = self.client.post("/api/v1/telemetry", json=payload, content_type="application/json")
        self.assertEqual(response.status_code, 422)

        # Verify no record was created
        events = TelemetryEvent.query.all()
        self.assertEqual(len(events), 0)

    def test_database_failure_triggers_rollback(self):
        """Test database failure triggers rollback and no partial record."""
        from sentinelforge.models import TelemetryEvent
        from unittest.mock import patch
        from sqlalchemy.exc import SQLAlchemyError

        # First, create a valid event to verify normal operation
        self.client.post("/api/v1/telemetry", json=self._valid_payload(), content_type="application/json")
        self.assertEqual(TelemetryEvent.query.count(), 1)

        # Now mock db.session.commit to raise a SQLAlchemyError
        with patch.object(db.session, "commit", side_effect=SQLAlchemyError("DB error")):
            response = self.client.post("/api/v1/telemetry", json=self._valid_payload(), content_type="application/json")
            self.assertEqual(response.status_code, 500)

        # Verify the failed request didn't leave a partial record
        # (The first one should still be there, no additional record)
        self.assertEqual(TelemetryEvent.query.count(), 1)

    def test_database_failure_no_internal_details_exposed(self):
        """Test database failure returns safe error without internal details."""
        from unittest.mock import patch
        from sqlalchemy.exc import SQLAlchemyError

        with patch.object(db.session, "commit", side_effect=SQLAlchemyError("SQL integrity constraint violation")):
            response = self.client.post("/api/v1/telemetry", json=self._valid_payload(), content_type="application/json")
            self.assertEqual(response.status_code, 500)
            data = response.get_json()

            # Check error structure
            self.assertEqual(data["status"], "error")
            self.assertEqual(data["error"]["code"], 500)
            self.assertEqual(data["error"]["message"], "Failed to persist telemetry event")

            # Check no internal details leaked
            response_text = str(data)
            self.assertNotIn("SQL", response_text)
            self.assertNotIn("integrity", response_text.lower())
            self.assertNotIn("constraint", response_text.lower())
            self.assertNotIn("traceback", response_text.lower())

    def _valid_payload(self) -> dict:
        """Return a minimal valid telemetry payload."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
            "process": {"name": "cmd.exe", "pid": 1234},
        }


class TelemetryQuarantineTestCase(unittest.TestCase):
    """Test cases for telemetry quarantine functionality."""

    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_malformed_json_creates_quarantine_record(self):
        """Test malformed JSON creates a quarantine record."""
        from sentinelforge.models import TelemetryQuarantine

        response = self.client.post(
            "/api/v1/telemetry",
            data="{ invalid json }",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

        quarantine_records = TelemetryQuarantine.query.all()
        self.assertEqual(len(quarantine_records), 1)
        record = quarantine_records[0]
        self.assertEqual(record.status, "quarantined")
        self.assertEqual(record.payload_type, "raw")
        self.assertIn("invalid json", record.original_payload)
        self.assertIsNone(record.validation_errors)

    def test_malformed_json_creates_audit_entry(self):
        """Test malformed JSON creates an audit log entry."""
        from sentinelforge.models import AuditLog

        self.client.post(
            "/api/v1/telemetry",
            data="{ invalid json }",
            content_type="application/json",
        )

        audit_logs = AuditLog.query.all()
        self.assertEqual(len(audit_logs), 1)
        audit = audit_logs[0]
        self.assertEqual(audit.action, "telemetry_malformed_json")
        self.assertEqual(audit.resource_type, "telemetry_quarantine")
        self.assertIsNotNone(audit.resource_id)
        self.assertEqual(audit.payload["status"], "quarantined")

    def test_malformed_json_returns_400(self):
        """Test malformed JSON returns 400 with safe error response."""
        response = self.client.post(
            "/api/v1/telemetry",
            data="{ invalid json }",
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data["error"]["code"], 400)
        self.assertEqual(data["error"]["message"], "Request body must be valid JSON")
        # Payload should not be exposed in response
        response_text = str(response.get_json())
        self.assertNotIn("invalid json", response_text)

    def test_schema_invalid_json_creates_quarantine_record(self):
        """Test schema-invalid JSON creates a quarantine record with errors."""
        from sentinelforge.models import TelemetryQuarantine

        # Missing required fields
        payload = {"event_type": "test", "source": "test"}  # no timestamp
        response = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422)

        quarantine_records = TelemetryQuarantine.query.all()
        self.assertEqual(len(quarantine_records), 1)
        record = quarantine_records[0]
        self.assertEqual(record.status, "quarantined")
        self.assertEqual(record.payload_type, "json")
        self.assertIsNotNone(record.validation_errors)
        self.assertEqual(len(record.validation_errors), 1)
        self.assertEqual(record.validation_errors[0]["field"], "timestamp")

    def test_schema_invalid_json_stores_validation_errors(self):
        """Test schema-invalid JSON stores structured validation errors."""
        from sentinelforge.models import TelemetryQuarantine

        payload = {"timestamp": "invalid", "event_type": "test", "source": "test"}
        self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )

        record = TelemetryQuarantine.query.first()
        self.assertIsNotNone(record.validation_errors)
        self.assertEqual(len(record.validation_errors), 1)
        self.assertEqual(record.validation_errors[0]["field"], "timestamp")
        # Message contains the validation error detail
        self.assertIn("datetime", record.validation_errors[0]["message"])

    def test_schema_invalid_json_creates_audit_entry(self):
        """Test schema-invalid JSON creates an audit log entry with error summary."""
        from sentinelforge.models import AuditLog

        payload = {"event_type": "test", "source": "test"}  # missing timestamp
        self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )

        audit_logs = AuditLog.query.all()
        self.assertEqual(len(audit_logs), 1)
        audit = audit_logs[0]
        self.assertEqual(audit.action, "telemetry_schema_invalid")
        self.assertEqual(audit.resource_type, "telemetry_quarantine")
        self.assertIn("Schema validation failed", audit.payload["error_summary"])

    def test_schema_invalid_json_returns_422(self):
        """Test schema-invalid JSON returns 422 with safe error response."""
        payload = {"event_type": "test", "source": "test"}  # missing timestamp
        response = self.client.post(
            "/api/v1/telemetry",
            json=payload,
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422)
        data = response.get_json()
        self.assertEqual(data["error"]["code"], 422)
        self.assertIn("details", data["error"])

    def test_malformed_event_metric_increments(self):
        """Test malformed event metric increments on both error types."""
        from sentinelforge.telemetry.quarantine import get_malformed_metric, _increment_malformed_metric

        # Reset counter
        _increment_malformed_metric.count = 0

        # Initial count should be 0
        self.assertEqual(get_malformed_metric(), 0)

        # Malformed JSON
        self.client.post("/api/v1/telemetry", data="{ invalid }", content_type="application/json")
        self.assertEqual(get_malformed_metric(), 1)

        # Schema invalid
        self.client.post("/api/v1/telemetry", json={"event_type": "test"}, content_type="application/json")
        self.assertEqual(get_malformed_metric(), 2)

    def test_valid_telemetry_still_persists_normally(self):
        """Test valid telemetry still persists to TelemetryEvent."""
        from sentinelforge.models import TelemetryEvent

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
            "process": {"name": "cmd.exe", "pid": 1234},
        }
        response = self.client.post("/api/v1/telemetry", json=payload, content_type="application/json")
        self.assertEqual(response.status_code, 202)

        events = TelemetryEvent.query.all()
        self.assertEqual(len(events), 1)

    def test_valid_telemetry_does_not_create_quarantine_record(self):
        """Test valid telemetry does not create any quarantine record."""
        from sentinelforge.models import TelemetryQuarantine

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
            "process": {"name": "cmd.exe", "pid": 1234},
        }
        self.client.post("/api/v1/telemetry", json=payload, content_type="application/json")

        quarantine_records = TelemetryQuarantine.query.all()
        self.assertEqual(len(quarantine_records), 0)

    def test_database_failure_rolls_back_quarantine_transaction(self):
        """Test database failure during quarantine rolls back the transaction."""
        from sentinelforge.models import TelemetryQuarantine
        from unittest.mock import patch
        from sqlalchemy.exc import SQLAlchemyError

        # Mock commit to fail during quarantine
        with patch.object(db.session, "commit", side_effect=SQLAlchemyError("DB error")):
            response = self.client.post(
                "/api/v1/telemetry",
                data="{ invalid json }",
                content_type="application/json",
            )
            self.assertEqual(response.status_code, 400)

        # Verify no quarantine record was persisted
        quarantine_records = TelemetryQuarantine.query.all()
        self.assertEqual(len(quarantine_records), 0)

    def test_quarantined_payload_not_exposed_in_api_response(self):
        """Test that quarantined payload is not exposed in API error response."""
        # Test malformed JSON
        response = self.client.post(
            "/api/v1/telemetry",
            data='{ "secret": "should-not-appear" }',
            content_type="application/json",
        )
        response_text = str(response.get_json())
        self.assertNotIn("should-not-appear", response_text)

        # Test schema invalid
        response = self.client.post(
            "/api/v1/telemetry",
            json={"timestamp": "invalid", "event_type": "test", "source": "test", "secret": "should-not-appear"},
            content_type="application/json",
        )
        response_text = str(response.get_json())
        self.assertNotIn("should-not-appear", response_text)

    def test_no_sensitive_payload_in_audit_logs(self):
        """Test that complete payloads are not written to audit logs."""
        from sentinelforge.models import AuditLog

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "test",
            "source": "test",
            "sensitive": "very-secret-data",
        }
        self.client.post("/api/v1/telemetry", json=payload, content_type="application/json")

        audit_logs = AuditLog.query.all()
        # Should have no audit logs for valid telemetry
        self.assertEqual(len(audit_logs), 0)

        # Now test malformed
        self.client.post("/api/v1/telemetry", data="{ invalid }", content_type="application/json")
        audit_logs = AuditLog.query.all()
        self.assertEqual(len(audit_logs), 1)
        audit_text = str(audit_logs[0].payload)
        self.assertNotIn("very-secret-data", audit_text)

    def test_malformed_json_stored_as_raw_text(self):
        """Test malformed JSON is stored as raw text (payload_type=raw)."""
        from sentinelforge.models import TelemetryQuarantine

        malformed = '{ "unclosed": "object" '
        self.client.post("/api/v1/telemetry", data=malformed, content_type="application/json")

        record = TelemetryQuarantine.query.first()
        self.assertEqual(record.payload_type, "raw")
        self.assertEqual(record.original_payload, malformed)

    def test_schema_invalid_json_stored_structurally(self):
        """Test schema-invalid JSON is stored with payload_type=json and errors."""
        from sentinelforge.models import TelemetryQuarantine

        payload = {"event_type": "test", "source": "test"}  # missing timestamp
        self.client.post("/api/v1/telemetry", json=payload, content_type="application/json")

        record = TelemetryQuarantine.query.first()
        self.assertEqual(record.payload_type, "json")
        self.assertIsNotNone(record.validation_errors)
        # Original payload stored as JSON text
        self.assertIn("event_type", record.original_payload)
        self.assertIn("source", record.original_payload)


if __name__ == "__main__":
    unittest.main()