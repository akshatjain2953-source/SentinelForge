"""SentinelForge database models."""
from datetime import datetime, timezone
from typing import Optional, List
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    UniqueConstraint,
    Index,
    JSON,
    Table,
)
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.dialects.postgresql import JSONB

from sentinelforge.database import db


class BaseModel(db.Model):
    """Base model with common fields."""
    __abstract__ = True

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


user_roles = Table(
    "user_roles",
    db.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("assigned_at", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False),
)


alert_attck = Table(
    "alert_attck",
    db.metadata,
    Column("alert_id", Integer, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True),
    Column("attck_technique_id", Integer, ForeignKey("attck_techniques.id", ondelete="CASCADE"), primary_key=True),
    Column("mapped_at", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False),
)


class User(BaseModel):
    """User account model."""
    __tablename__ = "users"

    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)

    roles = relationship("Role", secondary=user_roles, back_populates="users", lazy="dynamic")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="dynamic", cascade="all, delete-orphan")
    assigned_alerts = relationship("Alert", foreign_keys="Alert.assigned_to_id", back_populates="assigned_to", lazy="dynamic")
    owned_incidents = relationship("Incident", foreign_keys="Incident.owner_id", back_populates="owner", lazy="dynamic")

    def __repr__(self):
        return f"<User id={self.id} username={self.username}>"


class Role(BaseModel):
    """Role model for RBAC."""
    __tablename__ = "roles"

    name = Column(String(50), unique=True, nullable=False, index=True)
    is_default = Column(Boolean, default=False, nullable=False)

    users = relationship("User", secondary=user_roles, back_populates="roles", lazy="dynamic")

    def __repr__(self):
        return f"<Role id={self.id} name={self.name}>"


class TelemetryEvent(BaseModel):
    """Normalized security telemetry event."""
    __tablename__ = "telemetry_events"

    source = Column(String(100), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    payload = Column(JSON().with_variant(JSONB, "postgresql"), nullable=False)
    received_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    processed = Column(Boolean, default=False, nullable=False)

    detection_executions = relationship("DetectionExecution", back_populates="telemetry_event", lazy="dynamic", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_telemetry_source_type", "source", "event_type"),
        Index("ix_telemetry_received_processed", "received_at", "processed"),
    )

    def __repr__(self):
        return f"<TelemetryEvent id={self.id} source={self.source} type={self.event_type}>"


class DetectionRule(BaseModel):
    """Detection-as-Code rule model."""
    __tablename__ = "detection_rules"

    # YAML rule identifier (string, unique) - corresponds to YAML 'id' field
    rule_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, index=True)
    version = Column(String(50), nullable=False, default="1.0.0")
    # enabled boolean replaces status string - true=enabled, false=disabled
    enabled = Column(Boolean, default=True, nullable=False, index=True)
    author = Column(String(100), nullable=True)
    format = Column(String(50), nullable=False, default="yaml")
    query = Column(Text, nullable=False)
    # JSON/JSONB fields for flexible structured data
    tags = Column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    attck_techniques = Column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    test_cases = Column(JSON().with_variant(JSONB, "postgresql"), nullable=True)

    detection_executions = relationship("DetectionExecution", back_populates="detection_rule", lazy="dynamic", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_detection_rule_status_severity", "enabled", "severity"),
    )

    def __repr__(self):
        return f"<DetectionRule id={self.id} rule_id={self.rule_id} name={self.name} severity={self.severity} enabled={self.enabled}>"


class DetectionExecution(BaseModel):
    """Record of a detection rule evaluation against a telemetry event."""
    __tablename__ = "detection_executions"

    detection_rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    telemetry_event_id = Column(Integer, ForeignKey("telemetry_events.id", ondelete="CASCADE"), nullable=False, index=True)
    matched = Column(Boolean, default=False, nullable=False, index=True)
    error = Column(Text, nullable=True)
    execution_time_ms = Column(Integer, nullable=True)

    detection_rule = relationship("DetectionRule", back_populates="detection_executions", lazy="joined")
    telemetry_event = relationship("TelemetryEvent", back_populates="detection_executions", lazy="joined")
    alert = relationship("Alert", back_populates="detection_execution", uselist=False, cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_detection_execution_rule_event", "detection_rule_id", "telemetry_event_id"),
        Index("ix_detection_execution_matched_created", "matched", "created_at"),
    )

    def __repr__(self):
        return f"<DetectionExecution id={self.id} rule_id={self.detection_rule_id} matched={self.matched}>"


class Alert(BaseModel):
    """Alert generated from a detection match."""
    __tablename__ = "alerts"

    detection_rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    detection_execution_id = Column(Integer, ForeignKey("detection_executions.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    severity = Column(String(20), nullable=False, index=True)
    status = Column(String(30), nullable=False, default="new", index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    assigned_to_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)

    detection_rule = relationship("DetectionRule", backref="alerts", lazy="joined")
    detection_execution = relationship("DetectionExecution", back_populates="alert", lazy="joined")
    assigned_to = relationship("User", foreign_keys=[assigned_to_id], back_populates="assigned_alerts", lazy="joined")
    incident = relationship("Incident", back_populates="alerts", lazy="joined")
    attck_techniques = relationship("AttckTechnique", secondary=alert_attck, back_populates="alerts", lazy="dynamic")

    __table_args__ = (
        Index("ix_alert_status_severity", "status", "severity"),
        Index("ix_alert_assigned_status", "assigned_to_id", "status"),
        Index("ix_alert_incident_status", "incident_id", "status"),
    )

    def __repr__(self):
        return f"<Alert id={self.id} rule_id={self.detection_rule_id} severity={self.severity} status={self.status}>"


class Incident(BaseModel):
    """Incident grouping related alerts."""
    __tablename__ = "incidents"

    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default="open", index=True)
    severity = Column(String(20), nullable=False, index=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    resolution = Column(Text, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    owner = relationship("User", foreign_keys=[owner_id], back_populates="owned_incidents", lazy="joined")
    alerts = relationship("Alert", back_populates="incident", lazy="dynamic", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_incident_status_severity", "status", "severity"),
        Index("ix_incident_owner_status", "owner_id", "status"),
    )

    def __repr__(self):
        return f"<Incident id={self.id} title={self.title} status={self.status}>"


class AttckTechnique(BaseModel):
    """MITRE ATT&CK technique model."""
    __tablename__ = "attck_techniques"

    technique_id = Column(String(20), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    tactic = Column(String(50), nullable=True, index=True)
    is_subtechnique = Column(Boolean, default=False, nullable=False)
    parent_technique_id = Column(Integer, ForeignKey("attck_techniques.id", ondelete="SET NULL"), nullable=True, index=True)

    parent = relationship(
        "AttckTechnique",
        remote_side="AttckTechnique.id",
        backref="subtechniques",
        lazy="joined",
    )
    alerts = relationship("Alert", secondary=alert_attck, back_populates="attck_techniques", lazy="dynamic")

    __table_args__ = (
        Index("ix_attck_tactic_technique", "tactic", "technique_id"),
    )

    def __repr__(self):
        return f"<AttckTechnique id={self.id} technique_id={self.technique_id} name={self.name}>"


class AuditLog(BaseModel):
    """Immutable audit log for security-relevant actions."""
    __tablename__ = "audit_logs"

    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False, index=True)
    resource_id = Column(String(100), nullable=True, index=True)
    payload = Column(JSON().with_variant(JSONB, "postgresql"), nullable=True)

    user = relationship("User", back_populates="audit_logs", lazy="joined")

    __table_args__ = (
        Index("ix_audit_user_action", "user_id", "action"),
        Index("ix_audit_resource", "resource_type", "resource_id"),
        Index("ix_audit_created_action", "created_at", "action"),
    )

    def __repr__(self):
        return f"<AuditLog id={self.id} user_id={self.user_id} action={self.action} resource={self.resource_type}:{self.resource_id}>"


class TelemetryQuarantine(BaseModel):
    """Quarantined malformed or schema-invalid telemetry events.

    Stores events that failed JSON parsing or Pydantic schema validation
    for later analysis, reprocessing, or discarding.

    Important: The original_payload field stores raw text for malformed
    JSON (which cannot be parsed as JSON), and structured JSON for
    schema-invalid payloads that were valid JSON.
    """
    __tablename__ = "telemetry_quarantine"

    received_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    content_type = Column(String(100), nullable=True)
    original_payload = Column(Text, nullable=False)  # Raw text for malformed JSON; JSON text for schema-invalid
    payload_type = Column(String(20), nullable=False, default="raw")  # "raw" for malformed JSON, "json" for schema-invalid
    validation_errors = Column(JSON().with_variant(JSONB, "postgresql"), nullable=True)
    status = Column(String(20), nullable=False, default="quarantined", index=True)
    reprocessed_at = Column(DateTime(timezone=True), nullable=True)
    reprocessed_event_id = Column(Integer, ForeignKey("telemetry_events.id", ondelete="SET NULL"), nullable=True, index=True)

    reprocessed_event = relationship("TelemetryEvent", lazy="joined")

    __table_args__ = (
        Index("ix_quarantine_status_received", "status", "received_at"),
        Index("ix_quarantine_source_ip", "source_ip"),
    )

    def __repr__(self):
        return f"<TelemetryQuarantine id={self.id} status={self.status} source_ip={self.source_ip}>"