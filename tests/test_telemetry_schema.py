"""Tests for telemetry validation schema."""
import unittest
from datetime import datetime, timezone, timedelta
from sentinelforge.telemetry.schema import (
    TelemetrySchema,
    TelemetryBatchSchema,
    validate_telemetry,
    validate_telemetry_batch,
    ValidationError,
    HostSchema,
    UserSchema,
    ProcessSchema,
    NetworkSchema,
    FileSchema,
    MetadataSchema,
)


class TelemetrySchemaValidationTests(unittest.TestCase):
    """Tests for TelemetrySchema validation."""

    def test_valid_minimal_telemetry(self):
        """Test valid telemetry with required fields and one structured field."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
            "process": {"name": "cmd.exe", "pid": 1234},
        }
        result = validate_telemetry(data)
        self.assertEqual(result.event_type, "process_creation")
        self.assertEqual(result.source, "sysmon")
        self.assertIsNotNone(result.process)
        self.assertEqual(result.process.name, "cmd.exe")

    def test_valid_full_telemetry(self):
        """Test valid telemetry with all structured fields."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "network_connection",
            "source": "winlogbeat",
            "host": {"hostname": "DESKTOP-01", "ip": "192.168.1.10"},
            "user": {"name": "admin", "domain": "CORP"},
            "process": {"name": "chrome.exe", "pid": 5678},
            "network": {"protocol": "tcp", "dst_ip": "8.8.8.8", "dst_port": 443},
            "file": {"path": "C:\\temp\\file.txt", "size": 1024},
            "metadata": {"collector": "winlogbeat", "version": "8.0"},
        }
        result = validate_telemetry(data)
        self.assertIsNotNone(result.host)
        self.assertIsNotNone(result.user)
        self.assertIsNotNone(result.process)
        self.assertIsNotNone(result.network)
        self.assertIsNotNone(result.file)
        self.assertIsNotNone(result.metadata)

    def test_valid_with_raw_field(self):
        """Test valid telemetry with raw field only."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "custom_event",
            "source": "custom",
            "raw": {"custom_field": "value", "number": 42},
        }
        result = validate_telemetry(data)
        self.assertIsNotNone(result.raw)
        self.assertEqual(result.raw["custom_field"], "value")

    def test_missing_timestamp(self):
        """Test validation fails when timestamp is missing."""
        data = {
            "event_type": "process_creation",
            "source": "sysmon",
            "process": {"name": "cmd.exe"},
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertIn("timestamp", str(ctx.exception.errors))

    def test_missing_event_type(self):
        """Test validation fails when event_type is missing."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "sysmon",
            "process": {"name": "cmd.exe"},
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertIn("event_type", str(ctx.exception.errors))

    def test_missing_source(self):
        """Test validation fails when source is missing."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "process": {"name": "cmd.exe"},
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertIn("source", str(ctx.exception.errors))

    def test_empty_event_type(self):
        """Test validation fails when event_type is empty string."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "",
            "source": "sysmon",
            "process": {"name": "cmd.exe"},
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertIn("event_type", str(ctx.exception.errors))

    def test_whitespace_only_event_type(self):
        """Test validation fails when event_type is whitespace only."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "   ",
            "source": "sysmon",
            "process": {"name": "cmd.exe"},
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertIn("event_type", str(ctx.exception.errors))

    def test_empty_source(self):
        """Test validation fails when source is empty string."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "source": "",
            "process": {"name": "cmd.exe"},
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertIn("source", str(ctx.exception.errors))

    def test_no_structured_fields(self):
        """Test validation fails when no structured fields provided."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertTrue(any("structured field" in err.get("message", "") for err in ctx.exception.errors))

    def test_timestamp_too_far_future(self):
        """Test validation fails when timestamp is too far in future."""
        future = datetime.now(timezone.utc) + timedelta(minutes=10)
        data = {
            "timestamp": future.isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
            "process": {"name": "cmd.exe"},
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertTrue(any("future" in err.get("message", "") for err in ctx.exception.errors))

    def test_timestamp_small_future_allowed(self):
        """Test timestamp slightly in future is allowed (clock skew)."""
        future = datetime.now(timezone.utc) + timedelta(seconds=60)
        data = {
            "timestamp": future.isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
            "process": {"name": "cmd.exe"},
        }
        result = validate_telemetry(data)
        self.assertIsNotNone(result)

    def test_invalid_field_type(self):
        """Test validation fails when field type is wrong."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
            "process": {"pid": "not_an_integer"},
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertIn("pid", str(ctx.exception.errors))

    def test_string_length_validation(self):
        """Test string length limits are enforced."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "x" * 101,  # max 100
            "source": "sysmon",
            "process": {"name": "cmd.exe"},
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertIn("event_type", str(ctx.exception.errors))

    def test_network_port_bounds(self):
        """Test network port validation bounds."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "network_connection",
            "source": "sysmon",
            "network": {"dst_port": 70000},  # max 65535
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertIn("dst_port", str(ctx.exception.errors))

    def test_negative_values_rejected(self):
        """Test negative values are rejected for unsigned fields."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
            "process": {"pid": -1},
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertIn("pid", str(ctx.exception.errors))

    def test_unknown_fields_allowed_in_raw(self):
        """Test unknown fields can be put in raw."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "process_creation",
            "source": "sysmon",
            "process": {"name": "cmd.exe"},
            "raw": {"unknown_field": "allowed_here"},
        }
        result = validate_telemetry(data)
        self.assertEqual(result.raw["unknown_field"], "allowed_here")

    def test_nested_object_validation(self):
        """Test nested object validation works."""
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "file_modification",
            "source": "sysmon",
            "file": {"size": "not_a_number"},
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry(data)
        self.assertIn("size", str(ctx.exception.errors))


class TelemetryBatchValidationTests(unittest.TestCase):
    """Tests for TelemetryBatchSchema validation."""

    def test_valid_batch(self):
        """Test valid batch of telemetry events."""
        data = {
            "events": [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "process_creation",
                    "source": "sysmon",
                    "process": {"name": "cmd.exe"},
                },
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "network_connection",
                    "source": "sysmon",
                    "network": {"dst_ip": "8.8.8.8"},
                },
            ]
        }
        result = validate_telemetry_batch(data)
        self.assertEqual(len(result.events), 2)

    def test_empty_batch_rejected(self):
        """Test empty batch is rejected."""
        data = {"events": []}
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry_batch(data)
        self.assertIn("events", str(ctx.exception.errors))

    def test_batch_too_large(self):
        """Test batch exceeding max size is rejected."""
        events = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "test",
                "source": "test",
                "process": {"name": "test"},
            }
            for _ in range(1001)
        ]
        data = {"events": events}
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry_batch(data)
        self.assertIn("events", str(ctx.exception.errors))

    def test_duplicate_correlation_id_rejected(self):
        """Test duplicate correlation_id in batch is rejected."""
        corr_id = "550e8400-e29b-41d4-a716-446655440000"
        data = {
            "events": [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "test",
                    "source": "test",
                    "process": {"name": "test"},
                    "metadata": {"correlation_id": corr_id},
                },
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "test",
                    "source": "test",
                    "process": {"name": "test"},
                    "metadata": {"correlation_id": corr_id},
                },
            ]
        }
        with self.assertRaises(ValidationError) as ctx:
            validate_telemetry_batch(data)
        self.assertTrue(any("correlation_id" in err.get("message", "") or "correlation_id" in err.get("field", "") for err in ctx.exception.errors))

    def test_unique_correlation_ids_allowed(self):
        """Test unique correlation_ids in batch are allowed."""
        data = {
            "events": [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "test",
                    "source": "test",
                    "process": {"name": "test"},
                    "metadata": {"correlation_id": "550e8400-e29b-41d4-a716-446655440000"},
                },
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "test",
                    "source": "test",
                    "process": {"name": "test"},
                    "metadata": {"correlation_id": "550e8400-e29b-41d4-a716-446655440001"},
                },
            ]
        }
        result = validate_telemetry_batch(data)
        self.assertEqual(len(result.events), 2)


class NestedSchemaTests(unittest.TestCase):
    """Tests for nested schema validation."""

    def test_host_schema(self):
        """Test HostSchema validation."""
        host = HostSchema(hostname="test-host", ip="192.168.1.1")
        self.assertEqual(host.hostname, "test-host")

    def test_user_schema(self):
        """Test UserSchema validation."""
        user = UserSchema(name="admin", domain="CORP", groups=["admins", "users"])
        self.assertEqual(user.name, "admin")
        self.assertEqual(len(user.groups), 2)

    def test_process_schema(self):
        """Test ProcessSchema validation."""
        proc = ProcessSchema(pid=1234, name="cmd.exe", command_line="cmd.exe /c dir")
        self.assertEqual(proc.pid, 1234)

    def test_network_schema(self):
        """Test NetworkSchema validation."""
        net = NetworkSchema(protocol="tcp", src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443)
        self.assertEqual(net.protocol, "tcp")

    def test_file_schema(self):
        """Test FileSchema validation."""
        f = FileSchema(path="C:\\temp\\file.txt", size=2048, hash_sha256="a" * 64)
        self.assertEqual(f.size, 2048)

    def test_metadata_schema(self):
        """Test MetadataSchema validation."""
        meta = MetadataSchema(collector="sysmon", tags=["tag1", "tag2"])
        self.assertEqual(meta.collector, "sysmon")


if __name__ == "__main__":
    unittest.main()