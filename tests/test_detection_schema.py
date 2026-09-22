"""Tests for detection rule schema validation."""
import unittest
from sentinelforge.detection.schema import DetectionRuleSchema, TestCaseSchema


class DetectionRuleSchemaTests(unittest.TestCase):
    """Tests for DetectionRuleSchema validation."""

    def test_valid_complete_rule(self):
        """Test valid complete rule with all fields."""
        data = {
            "id": "test-rule-001",
            "name": "Suspicious Process Execution",
            "description": "Detects suspicious process execution patterns",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "author": "security-team",
            "tags": ["process", "execution", "suspicious"],
            "attck_techniques": ["T1059", "T1003"],
            "query": "SELECT * FROM telemetry WHERE process = 'cmd.exe' AND command LIKE '%/c%'",
            "test_cases": [
                {
                    "description": "positive test",
                    "telemetry": {"process": "cmd.exe", "command": "cmd.exe /c whoami"},
                    "expected": True
                },
                {
                    "description": "negative test",
                    "telemetry": {"process": "explorer.exe", "command": "explorer.exe"},
                    "expected": False
                }
            ]
        }
        rule = DetectionRuleSchema.model_validate(data)
        self.assertEqual(rule.id, "test-rule-001")
        self.assertEqual(rule.name, "Suspicious Process Execution")
        self.assertEqual(rule.severity, "high")
        self.assertTrue(rule.enabled)
        self.assertEqual(rule.version, "1.0.0")
        self.assertEqual(rule.query, "SELECT * FROM telemetry WHERE process = 'cmd.exe' AND command LIKE '%/c%'")
        self.assertEqual(len(rule.tags), 3)
        self.assertEqual(len(rule.attck_techniques), 2)
        self.assertEqual(len(rule.test_cases), 2)

    def test_valid_minimal_rule(self):
        """Test valid minimal rule with only required fields."""
        data = {
            "id": "test-rule-002",
            "name": "Minimal Rule",
            "severity": "medium",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        rule = DetectionRuleSchema.model_validate(data)
        self.assertEqual(rule.id, "test-rule-002")
        self.assertEqual(rule.name, "Minimal Rule")
        self.assertEqual(rule.severity, "medium")
        self.assertTrue(rule.enabled)
        self.assertEqual(rule.version, "1.0.0")
        self.assertIsNone(rule.description)
        self.assertIsNone(rule.author)
        self.assertIsNone(rule.tags)
        self.assertIsNone(rule.attck_techniques)
        self.assertIsNone(rule.test_cases)

    def test_missing_required_fields(self):
        """Test validation fails when required fields are missing."""
        # Missing id
        data = {
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

        # Missing name
        data = {
            "id": "test-rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

        # Missing severity
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

        # Missing enabled
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

        # Missing version
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

        # Missing query
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

    def test_invalid_severity(self):
        """Test validation rejects invalid severity values."""
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "invalid",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception) as ctx:
            DetectionRuleSchema.model_validate(data)
        self.assertIn("severity", str(ctx.exception).lower())

    def test_invalid_severity_case_insensitive(self):
        """Test severity validation is case-insensitive."""
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "HIGH",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        rule = DetectionRuleSchema.model_validate(data)
        self.assertEqual(rule.severity, "high")

    def test_invalid_field_types(self):
        """Test validation rejects invalid field types."""
        # severity as integer
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": 123,
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

        # version as integer
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": 1,
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

        # Note: Pydantic coerces string "true"/"false" to boolean by default
        # This is acceptable behavior for our use case

    def test_invalid_version_format(self):
        """Test validation rejects invalid version format."""
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "invalid-version",
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception) as ctx:
            DetectionRuleSchema.model_validate(data)
        self.assertIn("version", str(ctx.exception).lower())

    def test_valid_version_formats(self):
        """Test valid semantic version formats."""
        valid_versions = ["1.0.0", "1.0.0-alpha", "1.0.0-beta.1", "2.0.0+build.1"]
        for version in valid_versions:
            data = {
                "id": f"test-rule-{version}",
                "name": "Test Rule",
                "severity": "high",
                "enabled": True,
                "version": version,
                "query": "SELECT 1",
            }
            rule = DetectionRuleSchema.model_validate(data)
            self.assertEqual(rule.version, version)

    def test_optional_fields(self):
        """Test optional fields are handled correctly."""
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
            "description": "Test description",
            "author": "test-author",
            "tags": ["tag1", "tag2"],
            "attck_techniques": ["T1059", "T1003"],
            "test_cases": [
                {"description": "test", "telemetry": {}, "expected": True}
            ]
        }
        rule = DetectionRuleSchema.model_validate(data)
        self.assertEqual(rule.description, "Test description")
        self.assertEqual(rule.author, "test-author")
        self.assertEqual(rule.tags, ["tag1", "tag2"])
        self.assertEqual(rule.attck_techniques, ["T1059", "T1003"])
        self.assertEqual(len(rule.test_cases), 1)

    def test_empty_string_validation(self):
        """Test empty strings are rejected for required string fields."""
        # empty id
        data = {
            "id": "",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

        # whitespace only id
        data = {
            "id": "   ",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

        # empty name
        data = {
            "id": "test-rule",
            "name": "",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

        # empty query
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "",
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

    def test_attck_techniques_format(self):
        """Test ATT&CK technique ID format validation."""
        # Valid formats
        valid_techniques = ["T1059", "T1059.001", "T1003", "T1566.001"]
        for tech in valid_techniques:
            data = {
                "id": f"test-rule-{tech}",
                "name": "Test Rule",
                "severity": "high",
                "enabled": True,
                "version": "1.0.0",
                "query": "SELECT 1",
                "attck_techniques": [tech],
            }
            rule = DetectionRuleSchema.model_validate(data)
            self.assertEqual(rule.attck_techniques, [tech])

        # Invalid format
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
            "attck_techniques": ["INVALID"],
        }
        with self.assertRaises(Exception) as ctx:
            DetectionRuleSchema.model_validate(data)
        self.assertIn("attck", str(ctx.exception).lower())

    def test_test_cases_structure(self):
        """Test test_cases structure validation."""
        # Valid test cases
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
            "test_cases": [
                {
                    "description": "positive test",
                    "telemetry": {"process": "cmd.exe"},
                    "expected": True
                },
                {
                    "description": "negative test",
                    "telemetry": {"process": "notepad.exe"},
                    "expected": False
                }
            ]
        }
        rule = DetectionRuleSchema.model_validate(data)
        self.assertEqual(len(rule.test_cases), 2)
        self.assertEqual(rule.test_cases[0].description, "positive test")
        self.assertTrue(rule.test_cases[0].expected)
        self.assertFalse(rule.test_cases[1].expected)

        # Missing telemetry in test case
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
            "test_cases": [
                {"description": "test", "expected": True}
            ]
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

        # Invalid expected type
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
            "test_cases": [
                {"description": "test", "telemetry": {}, "expected": "yes"}
            ]
        }
        with self.assertRaises(Exception):
            DetectionRuleSchema.model_validate(data)

    def test_yaml_id_as_string(self):
        """Test that YAML id field is treated as string."""
        data = {
            "id": "rule-001",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        rule = DetectionRuleSchema.model_validate(data)
        self.assertEqual(rule.id, "rule-001")
        self.assertIsInstance(rule.id, str)

    def test_enabled_boolean(self):
        """Test enabled field is boolean."""
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": False,
            "version": "1.0.0",
            "query": "SELECT 1",
        }
        rule = DetectionRuleSchema.model_validate(data)
        self.assertFalse(rule.enabled)

        data["enabled"] = True
        rule = DetectionRuleSchema.model_validate(data)
        self.assertTrue(rule.enabled)

    def test_test_cases_structure(self):
        """Test test_cases structure with nested validation."""
        data = {
            "id": "test-rule",
            "name": "Test Rule",
            "severity": "high",
            "enabled": True,
            "version": "1.0.0",
            "query": "SELECT 1",
            "test_cases": [
                {
                    "description": "positive case",
                    "telemetry": {"process": "cmd.exe", "pid": 1234},
                    "expected": True
                },
                {
                    "description": "negative case",
                    "telemetry": {"process": "notepad.exe"},
                    "expected": False
                }
            ]
        }
        rule = DetectionRuleSchema.model_validate(data)
        self.assertEqual(len(rule.test_cases), 2)
        self.assertEqual(rule.test_cases[0].description, "positive case")
        self.assertEqual(rule.test_cases[0].telemetry["process"], "cmd.exe")
        self.assertTrue(rule.test_cases[0].expected)
        self.assertFalse(rule.test_cases[1].expected)


class TestCaseSchemaTests(unittest.TestCase):
    """Tests for TestCaseSchema validation."""

    def test_valid_test_case(self):
        """Test valid test case."""
        data = {
            "description": "Test case description",
            "telemetry": {"process": "cmd.exe"},
            "expected": True
        }
        tc = TestCaseSchema.model_validate(data)
        self.assertEqual(tc.description, "Test case description")
        self.assertEqual(tc.telemetry, {"process": "cmd.exe"})
        self.assertTrue(tc.expected)

    def test_required_fields(self):
        """Test required fields are enforced."""
        # Missing description
        with self.assertRaises(Exception):
            TestCaseSchema.model_validate({"telemetry": {}, "expected": True})

        # Missing telemetry
        with self.assertRaises(Exception):
            TestCaseSchema.model_validate({"description": "test", "expected": True})

        # Missing expected
        with self.assertRaises(Exception):
            TestCaseSchema.model_validate({"description": "test", "telemetry": {}})


if __name__ == "__main__":
    unittest.main()