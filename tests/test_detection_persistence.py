"""Tests for detection persistence (DetectionExecution + Alert)."""
import textwrap
import tempfile
import os
import unittest
from sentinelforge import create_app
from sentinelforge.database import db
from sentinelforge.detection.cache import RuleCache
from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.models import (
    TelemetryEvent,
    DetectionRule,
    DetectionExecution,
    Alert,
    AttckTechnique,
)


class DetectionPersistenceTests(unittest.TestCase):
    """Tests for DetectionEngine persistence functionality."""

    def _make_valid_rule(
        self,
        rule_id: str = "test-rule",
        name: str = "Test Rule",
        severity: str = "high",
        attck_techniques: list = None,
    ) -> str:
        """Return a minimal valid rule YAML string."""
        attck_str = ""
        if attck_techniques:
            attck_str = f"attck_techniques: {attck_techniques}\n"
        return textwrap.dedent(f"""\
            id: "{rule_id}"
            name: "{name}"
            severity: "{severity}"
            enabled: true
            version: "1.0.0"
            {attck_str}
            query: "SELECT * FROM telemetry WHERE event_type = 'process_creation'"
        """)

    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.tmpdir = tempfile.TemporaryDirectory()
        self.rules_dir = self.tmpdir.name

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        self.tmpdir.cleanup()

    def _write_rule(self, filename: str, content: str):
        """Helper to write a rule file."""
        path = os.path.join(self.rules_dir, filename)
        with open(path, "w") as f:
            f.write(content)

    def _create_telemetry_event(self, source="sysmon", event_type="process_creation", payload=None):
        """Create and persist a telemetry event."""
        if payload is None:
            payload = {"process": {"name": "cmd.exe"}}
        event = TelemetryEvent(
            source=source,
            event_type=event_type,
            payload=payload,
        )
        db.session.add(event)
        db.session.commit()
        return event

    def _create_detection_rule(self, rule_id, name, severity, attck_techniques=None):
        """Create and persist a detection rule in the database."""
        rule = DetectionRule(
            rule_id=rule_id,
            name=name,
            severity=severity,
            enabled=True,
            version="1.0.0",
            query="SELECT * FROM telemetry WHERE event_type = 'process_creation'",
            attck_techniques=attck_techniques or [],
        )
        db.session.add(rule)
        db.session.commit()
        return rule

    def _create_attck_techniques(self, technique_ids):
        """Create ATT&CK techniques in the database."""
        techniques = []
        for tech_id in technique_ids:
            tech = AttckTechnique(
                technique_id=tech_id,
                name=f"Technique {tech_id}",
                tactic="execution",
            )
            db.session.add(tech)
            techniques.append(tech)
        db.session.commit()
        return techniques

    def test_matched_rule_creates_detection_execution_and_alert(self):
        """Test that a matched rule creates DetectionExecution and Alert."""
        # Create rule in cache
        self._write_rule("rule.yaml", self._make_valid_rule("test-rule", "Test Rule"))

        # Create rule in database
        self._create_detection_rule("test-rule", "Test Rule", "high")

        # Create telemetry event in database
        event = self._create_telemetry_event()

        # Run detection with persistence
        cache = RuleCache(self.rules_dir)
        cache.load()
        engine = DetectionEngine(cache)

        results = engine.evaluate(event, persist=True)

        # Verify results
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].matched)

        # Verify DetectionExecution was created
        execution = db.session.query(DetectionExecution).first()
        self.assertIsNotNone(execution)
        self.assertEqual(execution.detection_rule_id, 1)
        self.assertEqual(execution.telemetry_event_id, event.id)
        self.assertTrue(execution.matched)
        self.assertEqual(execution.execution_time_ms, results[0].execution_time_ms)

        # Verify Alert was created
        alert = db.session.query(Alert).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.detection_rule_id, 1)
        self.assertEqual(alert.detection_execution_id, execution.id)
        self.assertEqual(alert.severity, "high")
        self.assertEqual(alert.status, "new")

    def test_non_matching_rule_creates_neither(self):
        """Test that a non-matching rule creates neither DetectionExecution nor Alert."""
        # Create rule in cache (different condition)
        rule_content = textwrap.dedent("""\
            id: "test-rule"
            name: "Test Rule"
            severity: "high"
            enabled: true
            version: "1.0.0"
            query: "SELECT * FROM telemetry WHERE event_type = 'process_creation' AND source = 'other'"
        """)
        self._write_rule("rule.yaml", rule_content)

        # Create rule in database
        self._create_detection_rule("test-rule", "Test Rule", "high")

        # Create telemetry event in database
        event = self._create_telemetry_event()

        # Run detection with persistence
        cache = RuleCache(self.rules_dir)
        cache.load()
        engine = DetectionEngine(cache)

        results = engine.evaluate(event, persist=True)

        # Verify results
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].matched)

        # Verify nothing was persisted
        self.assertEqual(db.session.query(DetectionExecution).count(), 0)
        self.assertEqual(db.session.query(Alert).count(), 0)

    def test_severity_populated_from_rule(self):
        """Test that alert severity is populated from the detection rule."""
        self._write_rule("rule.yaml", self._make_valid_rule("test-rule", "Test Rule", "critical"))

        self._create_detection_rule("test-rule", "Test Rule", "critical")
        event = self._create_telemetry_event()

        cache = RuleCache(self.rules_dir)
        cache.load()
        engine = DetectionEngine(cache)

        results = engine.evaluate(event, persist=True)

        self.assertTrue(results[0].matched)

        alert = db.session.query(Alert).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "critical")

    def test_attck_techniques_populated(self):
        """Test that ATT&CK techniques are populated from the rule."""
        self._write_rule(
            "rule.yaml",
            self._make_valid_rule("test-rule", "Test Rule", "high", ["T1059", "T1059.001"]),
        )

        # Create ATT&CK techniques in DB
        self._create_attck_techniques(["T1059", "T1059.001"])

        self._create_detection_rule("test-rule", "Test Rule", "high", ["T1059", "T1059.001"])
        event = self._create_telemetry_event()

        cache = RuleCache(self.rules_dir)
        cache.load()
        engine = DetectionEngine(cache)

        results = engine.evaluate(event, persist=True)

        self.assertTrue(results[0].matched)

        alert = db.session.query(Alert).first()
        self.assertIsNotNone(alert)

        # Verify ATT&CK techniques are associated
        techniques = alert.attck_techniques.all()
        self.assertEqual(len(techniques), 2)
        technique_ids = {t.technique_id for t in techniques}
        self.assertEqual(technique_ids, {"T1059", "T1059.001"})

    def test_evidence_populated(self):
        """Test that evidence is populated from telemetry event."""
        payload = {
            "process": {"name": "cmd.exe", "command_line": "cmd.exe /c whoami"},
            "user": {"name": "admin"},
        }
        self._write_rule("rule.yaml", self._make_valid_rule("test-rule", "Test Rule"))

        self._create_detection_rule("test-rule", "Test Rule", "high")
        event = self._create_telemetry_event(payload=payload)

        cache = RuleCache(self.rules_dir)
        cache.load()
        engine = DetectionEngine(cache)

        results = engine.evaluate(event, persist=True)

        self.assertTrue(results[0].matched)

        alert = db.session.query(Alert).first()
        self.assertIsNotNone(alert)

        evidence = alert.evidence
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["telemetry_event_id"], event.id)
        self.assertEqual(evidence["event_type"], "process_creation")
        self.assertEqual(evidence["source"], "sysmon")
        self.assertIn("matched_fields", evidence)
        self.assertIn("process", evidence["matched_fields"])
        self.assertIn("user", evidence["matched_fields"])

    def test_persistence_failure_rolls_back_safely(self):
        """Test that persistence failure rolls back and doesn't affect evaluation."""
        # Don't create rule in database - this will cause persistence to fail gracefully
        self._write_rule("rule.yaml", self._make_valid_rule("test-rule", "Test Rule"))

        # Note: NOT creating the rule in database
        event = self._create_telemetry_event()

        cache = RuleCache(self.rules_dir)
        cache.load()
        engine = DetectionEngine(cache)

        results = engine.evaluate(event, persist=True)

        # Evaluation should still work
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].matched)

        # Nothing should be persisted due to missing rule
        self.assertEqual(db.session.query(DetectionExecution).count(), 0)
        self.assertEqual(db.session.query(Alert).count(), 0)

    def test_rule_evaluation_error_does_not_create_alert(self):
        """Test that rule evaluation error does not create Alert."""
        # Create rule with invalid query
        rule_content = textwrap.dedent("""\
            id: "bad-rule"
            name: "Bad Rule"
            severity: "high"
            enabled: true
            version: "1.0.0"
            query: "INVALID SQL SYNTAX!!!"
        """)
        self._write_rule("bad.yaml", rule_content)

        # Also create a good rule
        self._write_rule("good.yaml", self._make_valid_rule("good-rule", "Good Rule"))

        # Create both rules in database
        self._create_detection_rule("bad-rule", "Bad Rule", "high")
        self._create_detection_rule("good-rule", "Good Rule", "high")

        event = self._create_telemetry_event()

        cache = RuleCache(self.rules_dir)
        cache.load()
        engine = DetectionEngine(cache)

        results = engine.evaluate(event, persist=True)

        # Should have 2 results
        self.assertEqual(len(results), 2)

        # Bad rule should have error, good rule should match
        bad_result = next(r for r in results if r.rule_id == "bad-rule")
        good_result = next(r for r in results if r.rule_id == "good-rule")

        self.assertFalse(bad_result.matched)
        self.assertIsNotNone(bad_result.error)
        self.assertTrue(good_result.matched)

        # Only good rule should have created DetectionExecution and Alert
        executions = db.session.query(DetectionExecution).all()
        self.assertEqual(len(executions), 1)
        self.assertEqual(executions[0].detection_rule.rule_id, "good-rule")

        alerts = db.session.query(Alert).all()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].detection_rule.rule_id, "good-rule")

    def test_multiple_matched_rules_create_multiple_executions_and_alerts(self):
        """Test that multiple matched rules create separate executions and alerts."""
        self._write_rule("rule1.yaml", self._make_valid_rule("rule-1", "Rule 1", "high"))
        self._write_rule("rule2.yaml", self._make_valid_rule("rule-2", "Rule 2", "medium"))

        self._create_detection_rule("rule-1", "Rule 1", "high")
        self._create_detection_rule("rule-2", "Rule 2", "medium")

        event = self._create_telemetry_event()

        cache = RuleCache(self.rules_dir)
        cache.load()
        engine = DetectionEngine(cache)

        results = engine.evaluate(event, persist=True)

        self.assertEqual(len(results), 2)
        self.assertTrue(all(r.matched for r in results))

        # Should have 2 executions and 2 alerts
        executions = db.session.query(DetectionExecution).all()
        self.assertEqual(len(executions), 2)

        alerts = db.session.query(Alert).all()
        self.assertEqual(len(alerts), 2)

        # Verify severities
        severities = {a.severity for a in alerts}
        self.assertEqual(severities, {"high", "medium"})

    def test_idempotency_duplicate_evaluation_creates_no_duplicates(self):
        """Test that repeated evaluation of same rule+event creates no duplicate records."""
        self._write_rule("rule.yaml", self._make_valid_rule("test-rule", "Test Rule", "high"))
        self._create_detection_rule("test-rule", "Test Rule", "high")
        event = self._create_telemetry_event()

        cache = RuleCache(self.rules_dir)
        cache.load()
        engine = DetectionEngine(cache)

        # First evaluation
        results1 = engine.evaluate(event, persist=True)
        self.assertEqual(len(results1), 1)
        self.assertTrue(results1[0].matched)
        self.assertEqual(results1[0].persistence_status, "success")

        # Verify exactly 1 execution and 1 alert
        self.assertEqual(db.session.query(DetectionExecution).count(), 1)
        self.assertEqual(db.session.query(Alert).count(), 1)

        execution1 = db.session.query(DetectionExecution).first()
        alert1 = db.session.query(Alert).first()

        # Second evaluation (same rule, same event)
        results2 = engine.evaluate(event, persist=True)
        self.assertEqual(len(results2), 1)
        self.assertTrue(results2[0].matched)
        self.assertEqual(results2[0].persistence_status, "success")

        # Should still have exactly 1 execution and 1 alert (no duplicates)
        self.assertEqual(db.session.query(DetectionExecution).count(), 1)
        self.assertEqual(db.session.query(Alert).count(), 1)

        # Should be the same records
        execution2 = db.session.query(DetectionExecution).first()
        alert2 = db.session.query(Alert).first()
        self.assertEqual(execution1.id, execution2.id)
        self.assertEqual(alert1.id, alert2.id)

    def test_idempotency_multiple_rules_no_cross_duplication(self):
        """Test that multiple rules on same event don't interfere with each other's idempotency."""
        self._write_rule("rule1.yaml", self._make_valid_rule("rule-1", "Rule 1", "high"))
        self._write_rule("rule2.yaml", self._make_valid_rule("rule-2", "Rule 2", "medium"))
        self._create_detection_rule("rule-1", "Rule 1", "high")
        self._create_detection_rule("rule-2", "Rule 2", "medium")
        event = self._create_telemetry_event()

        cache = RuleCache(self.rules_dir)
        cache.load()
        engine = DetectionEngine(cache)

        # First evaluation - both rules match
        results1 = engine.evaluate(event, persist=True)
        self.assertEqual(len(results1), 2)
        self.assertTrue(all(r.matched for r in results1))
        self.assertEqual(db.session.query(DetectionExecution).count(), 2)
        self.assertEqual(db.session.query(Alert).count(), 2)

        # Second evaluation - should not create duplicates
        results2 = engine.evaluate(event, persist=True)
        self.assertEqual(len(results2), 2)
        self.assertTrue(all(r.matched for r in results2))
        self.assertEqual(results2[0].persistence_status, "success")
        self.assertEqual(results2[1].persistence_status, "success")
        self.assertEqual(db.session.query(DetectionExecution).count(), 2)
        self.assertEqual(db.session.query(Alert).count(), 2)

    def test_idempotency_persistence_status_returns_success_on_duplicate(self):
        """Test that persistence_status is 'success' when duplicate is detected."""
        self._write_rule("rule.yaml", self._make_valid_rule("test-rule", "Test Rule", "critical"))
        self._create_detection_rule("test-rule", "Test Rule", "critical")
        event = self._create_telemetry_event()

        cache = RuleCache(self.rules_dir)
        cache.load()
        engine = DetectionEngine(cache)

        # First evaluation
        results1 = engine.evaluate(event, persist=True)
        self.assertEqual(results1[0].persistence_status, "success")

        # Second evaluation
        results2 = engine.evaluate(event, persist=True)
        self.assertEqual(results2[0].persistence_status, "success")

        # Third evaluation
        results3 = engine.evaluate(event, persist=True)
        self.assertEqual(results3[0].persistence_status, "success")


if __name__ == "__main__":
    unittest.main()