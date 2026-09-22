"""Telemetry validation schema for SentinelForge.

Defines the contract for incoming telemetry events before normalization.
Based on ECS-inspired unified schema as documented in ARCHITECTURE.md.
"""
from datetime import datetime, timedelta
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic.types import UUID4


class HostSchema(BaseModel):
    """Host information in telemetry event."""
    hostname: Optional[str] = Field(None, max_length=255)
    ip: Optional[str] = Field(None, max_length=45)
    mac: Optional[str] = Field(None, max_length=17)
    os: Optional[str] = Field(None, max_length=100)
    os_version: Optional[str] = Field(None, max_length=100)


class UserSchema(BaseModel):
    """User information in telemetry event."""
    name: Optional[str] = Field(None, max_length=255)
    domain: Optional[str] = Field(None, max_length=255)
    uid: Optional[str] = Field(None, max_length=100)
    groups: Optional[list[str]] = Field(None, max_length=50)


class ProcessSchema(BaseModel):
    """Process information in telemetry event."""
    pid: Optional[int] = Field(None, ge=0)
    ppid: Optional[int] = Field(None, ge=0)
    name: Optional[str] = Field(None, max_length=255)
    path: Optional[str] = Field(None, max_length=1024)
    command_line: Optional[str] = Field(None, max_length=4096)
    parent_name: Optional[str] = Field(None, max_length=255)
    parent_path: Optional[str] = Field(None, max_length=1024)
    user: Optional[str] = Field(None, max_length=255)
    integrity_level: Optional[str] = Field(None, max_length=50)


class NetworkSchema(BaseModel):
    """Network information in telemetry event."""
    protocol: Optional[str] = Field(None, max_length=20)
    direction: Optional[str] = Field(None, max_length=20)
    src_ip: Optional[str] = Field(None, max_length=45)
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_ip: Optional[str] = Field(None, max_length=45)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    bytes_sent: Optional[int] = Field(None, ge=0)
    bytes_received: Optional[int] = Field(None, ge=0)


class FileSchema(BaseModel):
    """File information in telemetry event."""
    path: Optional[str] = Field(None, max_length=1024)
    name: Optional[str] = Field(None, max_length=255)
    extension: Optional[str] = Field(None, max_length=50)
    size: Optional[int] = Field(None, ge=0)
    hash_md5: Optional[str] = Field(None, max_length=32)
    hash_sha1: Optional[str] = Field(None, max_length=40)
    hash_sha256: Optional[str] = Field(None, max_length=64)
    operation: Optional[str] = Field(None, max_length=50)


class MetadataSchema(BaseModel):
    """Metadata information in telemetry event."""
    version: Optional[str] = Field(None, max_length=50)
    collector: Optional[str] = Field(None, max_length=100)
    correlation_id: Optional[UUID4] = None
    tags: Optional[list[str]] = Field(None, max_length=100)
    extra: Optional[dict[str, Any]] = Field(None, max_length=20)


class TelemetrySchema(BaseModel):
    """Validated telemetry event schema.

    This is the input contract for POST /api/v1/telemetry.
    All fields are validated before normalization and persistence.
    """
    # Required fields
    timestamp: datetime = Field(..., description="Event timestamp in UTC")
    event_type: str = Field(..., min_length=1, max_length=100, description="Type of event (e.g., process_creation, network_connection)")
    source: str = Field(..., min_length=1, max_length=100, description="Telemetry source (e.g., sysmon, winlogbeat, atomic)")

    # Optional structured fields (ECS-inspired)
    host: Optional[HostSchema] = None
    user: Optional[UserSchema] = None
    process: Optional[ProcessSchema] = None
    network: Optional[NetworkSchema] = None
    file: Optional[FileSchema] = None
    metadata: Optional[MetadataSchema] = None

    # Additional raw data that doesn't fit structured fields
    raw: Optional[dict[str, Any]] = Field(None, max_length=50)

    @field_validator("event_type", "source")
    @classmethod
    def validate_non_empty_string(cls, v: str) -> str:
        """Ensure required strings are not just whitespace."""
        if not v or not v.strip():
            raise ValueError("must not be empty or whitespace")
        return v.strip()

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp_not_future(cls, v: datetime) -> datetime:
        """Reject timestamps too far in the future (allow small clock skew)."""
        now = datetime.now(v.tzinfo if v.tzinfo else None).replace(tzinfo=v.tzinfo)
        if v > now:
            # Allow up to 5 minutes future for clock skew
            max_future = now + timedelta(seconds=300)
            if v > max_future:
                raise ValueError("timestamp cannot be more than 5 minutes in the future")
        return v

    @model_validator(mode="after")
    def validate_at_least_one_structured_field(self) -> "TelemetrySchema":
        """Ensure at least one structured field is provided beyond required fields."""
        structured_fields = [self.host, self.user, self.process, self.network, self.file, self.metadata, self.raw]
        if not any(f is not None for f in structured_fields):
            raise ValueError("at least one structured field (host, user, process, network, file, metadata, raw) must be provided")
        return self


class TelemetryBatchSchema(BaseModel):
    """Batch telemetry validation schema.

    Accepts a list of telemetry events for bulk ingestion.
    """
    events: list[TelemetrySchema] = Field(..., min_length=1, max_length=1000)

    @field_validator("events")
    @classmethod
    def validate_unique_correlation_ids(cls, v: list[TelemetrySchema]) -> list[TelemetrySchema]:
        """Ensure correlation_ids are unique within batch if provided."""
        seen = set()
        for event in v:
            if event.metadata and event.metadata.correlation_id:
                if event.metadata.correlation_id in seen:
                    raise ValueError("duplicate correlation_id in batch")
                seen.add(event.metadata.correlation_id)
        return v


class ValidationError(Exception):
    """Custom exception for telemetry validation errors."""

    def __init__(self, message: str, errors: list[dict[str, Any]] | None = None):
        super().__init__(message)
        self.errors = errors or []


def validate_telemetry(data: dict[str, Any]) -> TelemetrySchema:
    """Validate a single telemetry event.

    Args:
        data: Raw telemetry data dictionary.

    Returns:
        Validated TelemetrySchema instance.

    Raises:
        ValidationError: If validation fails with detailed error information.
    """
    try:
        return TelemetrySchema.model_validate(data)
    except Exception as e:
        errors = []
        if hasattr(e, "errors"):
            for err in e.errors():
                errors.append({
                    "field": ".".join(str(x) for x in err.get("loc", [])),
                    "message": err.get("msg", "validation error"),
                    "type": err.get("type", "unknown"),
                })
        raise ValidationError("Telemetry validation failed", errors)


def validate_telemetry_batch(data: dict[str, Any]) -> TelemetryBatchSchema:
    """Validate a batch of telemetry events.

    Args:
        data: Raw batch data dictionary with "events" key.

    Returns:
        Validated TelemetryBatchSchema instance.

    Raises:
        ValidationError: If validation fails with detailed error information.
    """
    try:
        return TelemetryBatchSchema.model_validate(data)
    except Exception as e:
        errors = []
        if hasattr(e, "errors"):
            for err in e.errors():
                errors.append({
                    "field": ".".join(str(x) for x in err.get("loc", [])),
                    "message": err.get("msg", "validation error"),
                    "type": err.get("type", "unknown"),
                })
        raise ValidationError("Batch telemetry validation failed", errors)