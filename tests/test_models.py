"""Tests for SentinelForge database models."""
import unittest
from datetime import datetime, timezone
from sentinelforge import create_app
from sentinelforge.database import db
from sentinelforge.models import (
    User,
    Role,
    TelemetryEvent,
    DetectionRule,
    DetectionExecution,
    Alert,
    Incident,
    AttckTechnique,
    AuditLog,
    user_roles,
    alert_attck,
)


class ModelTestCase(unittest.TestCase):
    """Base test case with app context."""

    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()


class UserModelTests(ModelTestCase):
    """Tests for User model."""

    def test_create_user(self):
        """Test creating a user with required fields."""
        user = User(username="testuser", password_hash="hashed_password")
        db.session.add(user)
        db.session.commit()

        self.assertIsNotNone(user.id)
        self.assertEqual(user.username, "testuser")
        self.assertEqual(user.password_hash, "hashed_password")
        self.assertTrue(user.is_active)
        self.assertIsNone(user.last_login)
        self.assertIsNotNone(user.created_at)
        self.assertIsNotNone(user.updated_at)

    def test_username_unique_constraint(self):
        """Test username uniqueness constraint."""
        user1 = User(username="testuser", password_hash="hash1")
        user2 = User(username="testuser", password_hash="hash2")
        db.session.add(user1)
        db.session.commit()

        db.session.add(user2)
        with self.assertRaises(Exception):
            db.session.commit()

    def test_user_roles_relationship(self):
        """Test many-to-many user-roles relationship."""
        user = User(username="testuser", password_hash="hash")
        role1 = Role(name="admin")
        role2 = Role(name="analyst")
        db.session.add_all([user, role1, role2])
        db.session.commit()

        user.roles.append(role1)
        user.roles.append(role2)
        db.session.commit()

        self.assertEqual(user.roles.count(), 2)
        self.assertIn(role1, user.roles)
        self.assertIn(role2, user.roles)
        self.assertIn(user, role1.users)
        self.assertIn(user, role2.users)


class RoleModelTests(ModelTestCase):
    """Tests for Role model."""

    def test_create_role(self):
        """Test creating a role."""
        role = Role(name="admin", is_default=False)
        db.session.add(role)
        db.session.commit()

        self.assertIsNotNone(role.id)
        self.assertEqual(role.name, "admin")
        self.assertFalse(role.is_default)

    def test_role_name_unique(self):
        """Test role name uniqueness."""
        role1 = Role(name="admin")
        role2 = Role(name="admin")
        db.session.add(role1)
        db.session.commit()

        db.session.add(role2)
        with self.assertRaises(Exception):
            db.session.commit()


class TelemetryEventModelTests(ModelTestCase):
    """Tests for TelemetryEvent model."""

    def test_create_telemetry_event(self):
        """Test creating a telemetry event with JSON payload."""
        payload = {"process": "cmd.exe", "command": "whoami", "user": "admin"}
        event = TelemetryEvent(
            source="sysmon",
            event_type="process_creation",
            payload=payload,
        )
        db.session.add(event)
        db.session.commit()

        self.assertIsNotNone(event.id)
        self.assertEqual(event.source, "sysmon")
        self.assertEqual(event.event_type, "process_creation")
        self.assertEqual(event.payload, payload)
        self.assertFalse(event.processed)
        self.assertIsNotNone(event.received_at)

    def test_telemetry_json_field(self):
        """Test JSON/JSONB payload field stores complex data."""
        complex_payload = {
            "nested": {"key": "value"},
            "list": [1, 2, 3],
            "bool": True,
            "null": None,
        }
        event = TelemetryEvent(source="test", event_type="test", payload=complex_payload)
        db.session.add(event)
        db.session.commit()

        retrieved = TelemetryEvent.query.first()
        self.assertEqual(retrieved.payload, complex_payload)


class DetectionRuleModelTests(ModelTestCase):
    """Tests for DetectionRule model."""

    def test_create_detection_rule(self):
        """Test creating a detection rule."""
        rule = DetectionRule(
            rule_id="test-rule-001",
            name="Suspicious Process",
            description="Detects suspicious process execution",
            severity="high",
            query="SELECT * FROM telemetry WHERE process = 'cmd.exe'",
        )
        db.session.add(rule)
        db.session.commit()

        self.assertIsNotNone(rule.id)
        self.assertEqual(rule.rule_id, "test-rule-001")
        self.assertEqual(rule.name, "Suspicious Process")
        self.assertEqual(rule.severity, "high")
        self.assertTrue(rule.enabled)
        self.assertEqual(rule.version, "1.0.0")
        self.assertEqual(rule.format, "yaml")

    def test_detection_rule_defaults(self):
        """Test detection rule default values."""
        rule = DetectionRule(
            rule_id="test-rule-002",
            name="Test Rule",
            severity="medium",
            query="SELECT 1",
        )
        db.session.add(rule)
        db.session.commit()

        self.assertTrue(rule.enabled)
        self.assertEqual(rule.version, "1.0.0")
        self.assertEqual(rule.format, "yaml")


class DetectionExecutionModelTests(ModelTestCase):
    """Tests for DetectionExecution model."""

    def test_create_detection_execution(self):
        """Test creating a detection execution linking rule and event."""
        rule = DetectionRule(rule_id="test-rule-003", name="Test Rule", severity="high", query="SELECT 1")
        event = TelemetryEvent(source="test", event_type="test", payload={})
        db.session.add_all([rule, event])
        db.session.commit()

        execution = DetectionExecution(
            detection_rule_id=rule.id,
            telemetry_event_id=event.id,
            matched=True,
            execution_time_ms=15,
        )
        db.session.add(execution)
        db.session.commit()

        self.assertIsNotNone(execution.id)
        self.assertTrue(execution.matched)
        self.assertEqual(execution.execution_time_ms, 15)
        self.assertIsNone(execution.error)
        self.assertEqual(execution.detection_rule.id, rule.id)
        self.assertEqual(execution.telemetry_event.id, event.id)

    def test_detection_execution_no_match(self):
        """Test detection execution with no match."""
        rule = DetectionRule(rule_id="test-rule-004", name="Test Rule", severity="high", query="SELECT 1")
        event = TelemetryEvent(source="test", event_type="test", payload={})
        db.session.add_all([rule, event])
        db.session.commit()

        execution = DetectionExecution(
            detection_rule_id=rule.id,
            telemetry_event_id=event.id,
            matched=False,
        )
        db.session.add(execution)
        db.session.commit()

        self.assertFalse(execution.matched)

    def test_detection_execution_cascade_delete(self):
        """Test cascade delete when rule or event is deleted."""
        rule = DetectionRule(rule_id="test-rule-005", name="Test Rule", severity="high", query="SELECT 1")
        event = TelemetryEvent(source="test", event_type="test", payload={})
        db.session.add_all([rule, event])
        db.session.commit()

        execution = DetectionExecution(
            detection_rule_id=rule.id,
            telemetry_event_id=event.id,
            matched=True,
        )
        db.session.add(execution)
        db.session.commit()

        execution_id = execution.id
        db.session.delete(rule)
        db.session.commit()

        self.assertIsNone(db.session.get(DetectionExecution, execution_id))


class AlertModelTests(ModelTestCase):
    """Tests for Alert model."""

    def test_create_alert(self):
        """Test creating an alert from detection execution."""
        rule = DetectionRule(rule_id="test-rule-006", name="Test Rule", severity="high", query="SELECT 1")
        event = TelemetryEvent(source="test", event_type="test", payload={})
        db.session.add_all([rule, event])
        db.session.commit()

        execution = DetectionExecution(
            detection_rule_id=rule.id,
            telemetry_event_id=event.id,
            matched=True,
        )
        db.session.add(execution)
        db.session.commit()

        alert = Alert(
            detection_rule_id=rule.id,
            detection_execution_id=execution.id,
            severity="high",
            title="Suspicious Activity Detected",
            description="Details about the detection",
        )
        db.session.add(alert)
        db.session.commit()

        self.assertIsNotNone(alert.id)
        self.assertEqual(alert.severity, "high")
        self.assertEqual(alert.status, "new")
        self.assertEqual(alert.detection_execution_id, execution.id)

    def test_alert_detection_execution_unique(self):
        """Test one alert per detection execution."""
        rule = DetectionRule(rule_id="test-rule-007", name="Test Rule", severity="high", query="SELECT 1")
        event = TelemetryEvent(source="test", event_type="test", payload={})
        db.session.add_all([rule, event])
        db.session.commit()

        execution = DetectionExecution(
            detection_rule_id=rule.id,
            telemetry_event_id=event.id,
            matched=True,
        )
        db.session.add(execution)
        db.session.commit()

        alert1 = Alert(
            detection_rule_id=rule.id,
            detection_execution_id=execution.id,
            severity="high",
            title="Alert 1",
        )
        alert2 = Alert(
            detection_rule_id=rule.id,
            detection_execution_id=execution.id,
            severity="high",
            title="Alert 2",
        )
        db.session.add(alert1)
        db.session.commit()

        db.session.add(alert2)
        with self.assertRaises(Exception):
            db.session.commit()

    def test_alert_assigned_user(self):
        """Test alert assigned user relationship."""
        user = User(username="analyst", password_hash="hash")
        rule = DetectionRule(rule_id="test-rule-008", name="Test Rule", severity="high", query="SELECT 1")
        event = TelemetryEvent(source="test", event_type="test", payload={})
        db.session.add_all([user, rule, event])
        db.session.commit()

        execution = DetectionExecution(
            detection_rule_id=rule.id,
            telemetry_event_id=event.id,
            matched=True,
        )
        db.session.add(execution)
        db.session.commit()

        alert = Alert(
            detection_rule_id=rule.id,
            detection_execution_id=execution.id,
            severity="high",
            title="Test Alert",
            assigned_to_id=user.id,
        )
        db.session.add(alert)
        db.session.commit()

        self.assertEqual(alert.assigned_to.id, user.id)
        self.assertIn(alert, user.assigned_alerts)


class IncidentModelTests(ModelTestCase):
    """Tests for Incident model."""

    def test_create_incident(self):
        """Test creating an incident."""
        incident = Incident(
            title="Security Incident",
            description="Multiple alerts grouped",
            severity="critical",
            status="open",
        )
        db.session.add(incident)
        db.session.commit()

        self.assertIsNotNone(incident.id)
        self.assertEqual(incident.title, "Security Incident")
        self.assertEqual(incident.severity, "critical")
        self.assertEqual(incident.status, "open")

    def test_incident_alerts_relationship(self):
        """Test incident-alerts relationship with cascade."""
        user = User(username="owner", password_hash="hash")
        incident = Incident(title="Incident", severity="high", owner_id=user.id)
        db.session.add_all([user, incident])
        db.session.commit()

        rule = DetectionRule(rule_id="test-rule-009", name="Rule", severity="high", query="SELECT 1")
        event = TelemetryEvent(source="test", event_type="test", payload={})
        db.session.add_all([rule, event])
        db.session.commit()

        execution = DetectionExecution(
            detection_rule_id=rule.id,
            telemetry_event_id=event.id,
            matched=True,
        )
        db.session.add(execution)
        db.session.commit()

        alert = Alert(
            detection_rule_id=rule.id,
            detection_execution_id=execution.id,
            severity="high",
            title="Alert",
            incident_id=incident.id,
        )
        db.session.add(alert)
        db.session.commit()

        self.assertEqual(incident.alerts.count(), 1)
        self.assertEqual(alert.incident.id, incident.id)

    def test_incident_cascade_delete_alerts(self):
        """Test deleting incident cascades to alerts."""
        incident = Incident(title="Incident", severity="high")
        db.session.add(incident)
        db.session.commit()

        rule = DetectionRule(rule_id="test-rule-010", name="Rule", severity="high", query="SELECT 1")
        event = TelemetryEvent(source="test", event_type="test", payload={})
        db.session.add_all([rule, event])
        db.session.commit()

        execution = DetectionExecution(
            detection_rule_id=rule.id,
            telemetry_event_id=event.id,
            matched=True,
        )
        db.session.add(execution)
        db.session.commit()

        alert = Alert(
            detection_rule_id=rule.id,
            detection_execution_id=execution.id,
            severity="high",
            title="Alert",
            incident_id=incident.id,
        )
        db.session.add(alert)
        db.session.commit()

        alert_id = alert.id
        db.session.delete(incident)
        db.session.commit()

        self.assertIsNone(db.session.get(Alert, alert_id))


class AttckTechniqueModelTests(ModelTestCase):
    """Tests for ATT&CK Technique model."""

    def test_create_attck_technique(self):
        """Test creating an ATT&CK technique."""
        technique = AttckTechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactic="Execution",
            description="Adversaries may abuse command and script interpreters",
        )
        db.session.add(technique)
        db.session.commit()

        self.assertIsNotNone(technique.id)
        self.assertEqual(technique.technique_id, "T1059")
        self.assertEqual(technique.tactic, "Execution")
        self.assertFalse(technique.is_subtechnique)

    def test_attck_technique_unique_id(self):
        """Test technique_id uniqueness."""
        tech1 = AttckTechnique(technique_id="T1059", name="Test", tactic="Execution")
        tech2 = AttckTechnique(technique_id="T1059", name="Test 2", tactic="Execution")
        db.session.add(tech1)
        db.session.commit()

        db.session.add(tech2)
        with self.assertRaises(Exception):
            db.session.commit()

    def test_attck_subtechnique(self):
        """Test subtechnique parent relationship."""
        parent = AttckTechnique(technique_id="T1059", name="Parent", tactic="Execution")
        db.session.add(parent)
        db.session.flush()  # Assign ID before creating child

        child = AttckTechnique(
            technique_id="T1059.001",
            name="PowerShell",
            tactic="Execution",
            is_subtechnique=True,
            parent_technique_id=parent.id,
        )
        db.session.add(child)
        db.session.commit()

        self.assertEqual(child.parent.id, parent.id)
        self.assertIn(child, parent.subtechniques)

    def test_alert_attck_many_to_many(self):
        """Test many-to-many alert-ATT&CK mapping."""
        technique1 = AttckTechnique(technique_id="T1059", name="Command Interpreter", tactic="Execution")
        technique2 = AttckTechnique(technique_id="T1003", name="OS Credential Dumping", tactic="Credential Access")
        rule = DetectionRule(rule_id="test-rule-012", name="Rule", severity="high", query="SELECT 1")
        event = TelemetryEvent(source="test", event_type="test", payload={})
        db.session.add_all([technique1, technique2, rule, event])
        db.session.commit()

        execution = DetectionExecution(
            detection_rule_id=rule.id,
            telemetry_event_id=event.id,
            matched=True,
        )
        db.session.add(execution)
        db.session.commit()

        alert = Alert(
            detection_rule_id=rule.id,
            detection_execution_id=execution.id,
            severity="high",
            title="Alert",
        )
        db.session.add(alert)
        db.session.commit()

        alert.attck_techniques.append(technique1)
        alert.attck_techniques.append(technique2)
        db.session.commit()

        self.assertEqual(alert.attck_techniques.count(), 2)
        self.assertIn(technique1, alert.attck_techniques)
        self.assertIn(alert, technique1.alerts)


class AuditLogModelTests(ModelTestCase):
    """Tests for AuditLog model."""

    def test_create_audit_log(self):
        """Test creating an audit log entry."""
        user = User(username="admin", password_hash="hash")
        db.session.add(user)
        db.session.commit()

        audit = AuditLog(
            user_id=user.id,
            action="login",
            resource_type="user",
            resource_id=str(user.id),
            payload={"ip": "127.0.0.1", "method": "password"},
        )
        db.session.add(audit)
        db.session.commit()

        self.assertIsNotNone(audit.id)
        self.assertEqual(audit.action, "login")
        self.assertEqual(audit.resource_type, "user")
        self.assertEqual(audit.payload["ip"], "127.0.0.1")
        self.assertEqual(audit.user.id, user.id)

    def test_audit_log_without_user(self):
        """Test audit log can exist without user (system actions)."""
        audit = AuditLog(
            action="system_startup",
            resource_type="system",
            resource_id="server-1",
            payload={"version": "0.1.0"},
        )
        db.session.add(audit)
        db.session.commit()

        self.assertIsNone(audit.user_id)
        self.assertIsNone(audit.user)

    def test_audit_log_json_payload(self):
        """Test audit log payload stores JSON data."""
        payload = {
            "before": {"status": "new"},
            "after": {"status": "resolved"},
            "changed_fields": ["status"],
        }
        audit = AuditLog(
            action="alert_updated",
            resource_type="alert",
            resource_id="123",
            payload=payload,
        )
        db.session.add(audit)
        db.session.commit()

        retrieved = AuditLog.query.first()
        self.assertEqual(retrieved.payload, payload)


class BaseModelTimestampTests(ModelTestCase):
    """Tests for base model timestamps."""

    def test_created_at_auto_set(self):
        """Test created_at is automatically set."""
        user = User(username="test", password_hash="hash")
        db.session.add(user)
        db.session.commit()

        self.assertIsNotNone(user.created_at)
        self.assertIsInstance(user.created_at, datetime)

    def test_updated_at_auto_set_on_update(self):
        """Test updated_at is automatically updated."""
        user = User(username="test", password_hash="hash")
        db.session.add(user)
        db.session.commit()

        original_updated = user.updated_at
        user.username = "updated"
        db.session.commit()

        self.assertNotEqual(user.updated_at, original_updated)
        self.assertGreater(user.updated_at, original_updated)


if __name__ == "__main__":
    unittest.main()