"""Quarantine service for malformed and schema-invalid telemetry events."""
from datetime import datetime, timezone
from typing import Any, Optional
from flask import request
from sentinelforge.database import db
from sentinelforge.models import TelemetryQuarantine, AuditLog, TelemetryEvent
from sentinelforge.telemetry.schema import ValidationError, validate_telemetry


def _get_client_ip() -> Optional[str]:
    """Extract client IP from request, handling proxies."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr


def _create_audit_entry(quarantine_id: int, action: str, status: str, error_summary: Optional[str] = None) -> None:
    """Create an audit log entry for quarantine actions.

    Does not store the raw payload in audit logs.
    """
    payload = {
        "quarantine_id": quarantine_id,
        "status": status,
    }
    if error_summary:
        payload["error_summary"] = error_summary[:200]  # Truncate for safety

    audit = AuditLog(
        user_id=None,  # No authenticated user for ingestion
        action=action,
        resource_type="telemetry_quarantine",
        resource_id=str(quarantine_id),
        payload=payload,
    )
    db.session.add(audit)


def _increment_malformed_metric() -> None:
    """Increment the malformed event counter.

    Uses a simple in-memory counter. In production this could be
    replaced with a proper metrics system.
    """
    if not hasattr(_increment_malformed_metric, "count"):
        _increment_malformed_metric.count = 0
    _increment_malformed_metric.count += 1


def get_malformed_metric() -> int:
    """Get the current malformed event count."""
    return getattr(_increment_malformed_metric, "count", 0)


def quarantine_malformed_json(
    raw_body: str,
    content_type: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> TelemetryQuarantine:
    """Quarantine a telemetry event that failed JSON parsing.

    Args:
        raw_body: The raw request body as text (malformed JSON).
        content_type: The request Content-Type header.
        source_ip: Client IP address (auto-detected if None).

    Returns:
        The created TelemetryQuarantine record.
    """
    if source_ip is None:
        source_ip = _get_client_ip()

    quarantine = TelemetryQuarantine(
        source_ip=source_ip,
        content_type=content_type,
        original_payload=raw_body,
        payload_type="raw",  # Malformed JSON stored as raw text
        validation_errors=None,  # No structured errors for parse failure
        status="quarantined",
    )
    db.session.add(quarantine)
    db.session.flush()  # Get the ID for audit log

    _create_audit_entry(quarantine.id, "telemetry_malformed_json", "quarantined")
    _increment_malformed_metric()

    return quarantine


def quarantine_schema_invalid(
    raw_body: str,
    validation_errors: list[dict[str, Any]],
    content_type: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> TelemetryQuarantine:
    """Quarantine a telemetry event that passed JSON parsing but failed schema validation.

    Args:
        raw_body: The raw request body as text (valid JSON but invalid schema).
        validation_errors: List of validation error dicts from Pydantic.
        content_type: The request Content-Type header.
        source_ip: Client IP address (auto-detected if None).

    Returns:
        The created TelemetryQuarantine record.
    """
    if source_ip is None:
        source_ip = _get_client_ip()

    # Store validation errors as structured JSON
    error_summary = f"Schema validation failed: {len(validation_errors)} error(s)"
    quarantine = TelemetryQuarantine(
        source_ip=source_ip,
        content_type=content_type,
        original_payload=raw_body,
        payload_type="json",  # Valid JSON, schema-invalid
        validation_errors=validation_errors,
        status="quarantined",
    )
    db.session.add(quarantine)
    db.session.flush()  # Get the ID for audit log

    _create_audit_entry(quarantine.id, "telemetry_schema_invalid", "quarantined", error_summary)
    _increment_malformed_metric()

    return quarantine


def get_quarantine_status(quarantine_id: int) -> Optional[TelemetryQuarantine]:
    """Get a quarantine record by ID."""
    return TelemetryQuarantine.query.get(quarantine_id)


def list_quarantined(
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[TelemetryQuarantine]:
    """List quarantined events with optional status filter."""
    query = TelemetryQuarantine.query.order_by(TelemetryQuarantine.received_at.desc())
    if status:
        query = query.filter(TelemetryQuarantine.status == status)
    return query.limit(limit).offset(offset).all()


def get_quarantine_metrics() -> dict[str, int]:
    """Get quarantine metrics: total and per-status counts."""
    from sqlalchemy import func

    total = TelemetryQuarantine.query.count()
    by_status = dict(
        db.session.query(TelemetryQuarantine.status, func.count(TelemetryQuarantine.id))
        .group_by(TelemetryQuarantine.status)
        .all()
    )
    return {
        "total": total,
        **by_status,
    }


def reprocess_quarantined(quarantine_id: int) -> tuple[bool, Optional[TelemetryEvent], Optional[str]]:
    """Attempt to reprocess a quarantined event.

    Only works for payload_type="json" (schema-invalid) since malformed
    JSON cannot be parsed.

    Args:
        quarantine_id: ID of the quarantine record to reprocess.

    Returns:
        Tuple of (success, TelemetryEvent|None, error_message|None).
    """
    quarantine = TelemetryQuarantine.query.get(quarantine_id)
    if not quarantine:
        return False, None, "Quarantine record not found"

    if quarantine.status != "quarantined":
        return False, None, f"Already {quarantine.status}"

    if quarantine.payload_type != "json":
        return False, None, "Cannot reprocess malformed JSON (payload_type=raw)"

    # Try to validate the stored payload
    try:
        import json
        payload = json.loads(quarantine.original_payload)
        validated = validate_telemetry(payload)
    except (json.JSONDecodeError, ValidationError) as e:
        return False, None, str(e)

    # Create and persist the telemetry event
    from sentinelforge.telemetry.normalize import create_telemetry_event

    event = create_telemetry_event(validated)
    db.session.add(event)
    db.session.flush()

    # Update quarantine record
    quarantine.status = "reprocessed"
    quarantine.reprocessed_at = datetime.now(timezone.utc)
    quarantine.reprocessed_event_id = event.id

    # Audit log
    _create_audit_entry(quarantine.id, "telemetry_reprocessed", "reprocessed")

    return True, event, None


def discard_quarantined(quarantine_id: int) -> bool:
    """Mark a quarantined event as discarded (no longer actionable)."""
    quarantine = TelemetryQuarantine.query.get(quarantine_id)
    if not quarantine:
        return False

    quarantine.status = "discarded"
    db.session.add(quarantine)

    _create_audit_entry(quarantine.id, "telemetry_discarded", "discarded")
    return True