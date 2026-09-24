"""Tests for the detection engine core evaluation logic."""
import textwrap
import tempfile
import os
import unittest
from sentinelforge import create_app
from sentinelforge.detection.cache import RuleCache
from sentinelforge.detection.engine import DetectionEngine, DetectionResult
from sentinelforge.detection.loader import load_rules
from sentinelforge.detection.schema import DetectionRuleSchema


class DetectionEngineTests(unittest.TestCase):
    """Tests for the DetectionEngine core evaluation logic."""

    def _make_valid_rule(self, rule_id: str = "test-rule", name: str = "Test Rule") -> str:
        """Return a minimal valid rule YAML string."""
        return textwrap.dedent(f"""\
            id: "{rule_id}"
            name: "{name}"
            severity: "high"
            enabled: true
            version: "1.0.0"
            query: "SELECT * FROM telemetry WHERE event_type = 'process_creation'"
        """)

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.rules_dir = self.tmpdir.name

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write_rule(self, filename: str, content: str = None, rule_id: str = None, name: str = None):
        """Helper to write a rule file."""
        path = os.path.join(self.rules_dir, filename)
        if content is None:
            if rule_id is None and name is None:
                content = self._make_valid_rule(
                    filename.replace(".yaml", "").replace(".yml", ""),
                    filename.replace(".yaml", "").replace(".yml", "")
                )
            else:
                content = self._make_valid_rule(rule_id or filename.replace(".yaml", "").replace(".yml", ""), name or rule_id or filename.replace(".yaml", "").replace(".yml", ""))
        with open(path, "w") as f:
            f.write(content)

    def test_matching_rule(self):
        """Test that a matching rule returns matched=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_content = textwrap.dedent("""\
                id: "test-rule"
                name: "Test Rule"
                severity: "high"
                enabled: true
                version: "1.0.0"
                query: "SELECT * FROM telemetry WHERE event_type = 'process_creation'"
            """)
            rule_file = os.path.join(tmpdir, "rule.yaml")
            with open(rule_file, "w") as f:
                f.write(rule_content)

            cache = RuleCache(tmpdir)
            cache.load()
            engine = DetectionEngine(cache)

            from sentinelforge.models import TelemetryEvent
            event = TelemetryEvent(
                source="sysmon",
                event_type="process_creation",
                payload={
                    "process": {"name": "cmd.exe", "command_line": "cmd.exe /c whoami"}
                }
            )

            results = engine.evaluate(event)
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0].matched)
            self.assertEqual(results[0].rule_id, "test-rule")

    def test_non_matching_rule(self):
        """Test that a non-matching rule returns matched=False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_content = textwrap.dedent("""\
                id: "test-rule"
                name: "Test Rule"
                severity: "high"
                enabled: true
                version: "1.0.0"
                query: "SELECT * FROM telemetry WHERE event_type = 'process_creation' AND source = 'other'"
            """)

            with open(os.path.join(tmpdir, "rule.yaml"), "w") as f:
                f.write(rule_content)

            from sentinelforge.models import TelemetryEvent
            event = TelemetryEvent(
                source="sysmon",
                event_type="process_creation",
                payload={"process": {"name": "cmd.exe"}}
            )

            cache = RuleCache(tmpdir)
            cache.load()
            engine = DetectionEngine(cache)

            results = engine.evaluate(TelemetryEvent(
                source="sysmon",
                event_type="process_creation",
                payload={"process": {"name": "cmd.exe"}}
            ))

            self.assertEqual(len(results), 1)
            self.assertFalse(results[0].matched)

    def test_multiple_rules(self):
        """Test evaluation of multiple rules."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Matching rule
            with open(os.path.join(tmpdir, "rule1.yaml"), "w") as f:
                f.write(textwrap.dedent("""\
                    id: "rule-1"
                    name: "Rule 1"
                    severity: "high"
                    enabled: true
                    version: "1.0.0"
                    query: "SELECT * FROM telemetry WHERE event_type = 'process_creation' AND source = 'sysmon'"
                """))
            # Non-matching rule (same event_type, different condition)
            with open(os.path.join(tmpdir, "rule2.yaml"), "w") as f:
                f.write(textwrap.dedent("""\
                    id: "rule-2"
                    name: "Rule 2"
                    severity: "high"
                    enabled: true
                    version: "1.0.0"
                    query: "SELECT * FROM telemetry WHERE event_type = 'process_creation' AND source = 'other'"
                """))

            cache = RuleCache(tmpdir)
            cache.load()
            engine = DetectionEngine(cache)

            from sentinelforge.models import TelemetryEvent
            event = TelemetryEvent(
                source="sysmon",
                event_type="process_creation",
                payload={"process": {"name": "cmd.exe"}}
            )

            results = engine.evaluate(TelemetryEvent(
                source="sysmon",
                event_type="process_creation",
                payload={"process": {"name": "cmd.exe"}}
            ))

            self.assertEqual(len(results), 2)
            matched_rules = [r for r in results if r.matched]
            self.assertEqual(len(matched_rules), 1)
            self.assertEqual(matched_rules[0].rule_id, "rule-1")

    def test_disabled_rule_skipped(self):
        """Test that disabled rules are not evaluated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "enabled.yaml"), "w") as f:
                f.write(textwrap.dedent("""\
                    id: "enabled-rule"
                    name: "Enabled Rule"
                    severity: "high"
                    enabled: true
                    version: "1.0.0"
                    query: "SELECT * FROM telemetry WHERE event_type = 'process_creation'"
                """))
            with open(os.path.join(tmpdir, "disabled.yaml"), "w") as f:
                f.write(textwrap.dedent("""\
                    id: "disabled-rule"
                    name: "Disabled Rule"
                    severity: "high"
                    enabled: false
                    version: "1.0.0"
                    query: "SELECT * FROM telemetry WHERE event_type = 'process_creation'"
                """))

            cache = RuleCache(tmpdir)
            cache.load()
            engine = DetectionEngine(cache)

            from sentinelforge.models import TelemetryEvent
            event = TelemetryEvent(
                source="sysmon",
                event_type="process_creation",
                payload={"process": {"name": "cmd.exe"}}
            )

            results = engine.evaluate(TelemetryEvent(
                source="sysmon",
                event_type="process_creation",
                payload={"process": {"name": "cmd.exe"}}
            ))

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].rule_id, "enabled-rule")
            self.assertTrue(results[0].matched)

    def test_invalid_query_handled_safely(self):
        """Test that malformed/invalid queries are handled safely."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "bad.yaml"), "w") as f:
                f.write(textwrap.dedent("""\
                    id: "bad-rule"
                    name: "Bad Rule"
                    severity: "high"
                    enabled: true
                    version: "1.0.0"
                    query: "INVALID SQL SYNTAX!!!"
                """))
            with open(os.path.join(tmpdir, "good.yaml"), "w") as f:
                f.write(textwrap.dedent("""\
                    id: "good-rule"
                    name: "Good Rule"
                    severity: "high"
                    enabled: true
                    version: "1.0.0"
                    query: "SELECT * FROM telemetry WHERE event_type = 'process_creation'"
                """))

            cache = RuleCache(tmpdir)
            cache.load()
            engine = DetectionEngine(cache)

            from sentinelforge.models import TelemetryEvent
            event = TelemetryEvent(
                source="sysmon",
                event_type="process_creation",
                payload={"process": {"name": "cmd.exe"}}
            )

            results = engine.evaluate(TelemetryEvent(
                source="sysmon",
                event_type="process_creation",
                payload={"process": {"name": "cmd.exe"}}
            ))

            # Should have results for both rules
            self.assertEqual(len(results), 2)

            # Bad rule should have matched=False and error set
            bad_result = next(r for r in results if r.rule_id == "bad-rule")
            self.assertFalse(bad_result.matched)
            self.assertIsNotNone(bad_result.error)

            # Good rule should still match
            good_result = next(r for r in results if r.rule_id == "good-rule")
            self.assertTrue(good_result.matched)
            self.assertIsNone(good_result.error)

    def test_failing_rule_does_not_stop_others(self):
        """Test that one rule failing doesn't stop evaluation of others."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Bad rule (syntax error)
            with open(os.path.join(tmpdir, "bad.yaml"), "w") as f:
                f.write(textwrap.dedent("""\
                    id: "bad-rule"
                    name: "Bad Rule"
                    severity: "high"
                    enabled: true
                    version: "1.0.0"
                    query: "INVALID SQL SYNTAX!!!"
                """))
            # Good rule 1
            with open(os.path.join(tmpdir, "good1.yaml"), "w") as f:
                f.write(textwrap.dedent("""\
                    id: "good-1"
                    name: "Good Rule 1"
                    severity: "high"
                    enabled: true
                    version: "1.0.0"
                    query: "SELECT * FROM telemetry WHERE event_type = 'process_creation'"
                """))
            # Good rule 2
            with open(os.path.join(tmpdir, "good2.yaml"), "w") as f:
                f.write(textwrap.dedent("""\
                    id: "good-2"
                    name: "Good Rule 2"
                    severity: "high"
                    enabled: true
                    version: "1.0.0"
                    query: "SELECT * FROM telemetry WHERE event_type = 'process_creation'"
                """))

            cache = RuleCache(tmpdir)
            cache.load()
            engine = DetectionEngine(cache)

            from sentinelforge.models import TelemetryEvent
            event = TelemetryEvent(
                source="sysmon",
                event_type="process_creation",
                payload={"process": {"name": "cmd.exe"}}
            )

            results = engine.evaluate(TelemetryEvent(
                source="sysmon",
                event_type="process_creation",
                payload={"process": {"name": "cmd.exe"}}
            ))

            # Should have results for all 3 rules
            self.assertEqual(len(results), 3)

            # Bad rule should have error
            bad_result = next(r for r in results if r.rule_id == "bad-rule")
            self.assertFalse(bad_result.matched)
            self.assertIsNotNone(bad_result.error)

            # Good rules should still match
            good1 = next(r for r in results if r.rule_id == "good-1")
            good2 = next(r for r in results if r.rule_id == "good-2")
            self.assertTrue(good1.matched)
            self.assertTrue(good2.matched)
            self.assertIsNone(good1.error)
            self.assertIsNone(good2.error)


if __name__ == "__main__":
    unittest.main()