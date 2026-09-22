"""Telemetry normalization for SentinelForge.

Converts validated Pydantic telemetry schema into normalized
representation suitable for database persistence.
"""
from datetime import datetime
from typing import Any, Optional
from sentinelforge.telemetry.schema import TelemetrySchema


def normalize_telemetry(validated: TelemetrySchema) -> dict[str, Any]:
    """Normalize a validated telemetry event for database storage.

    Args:
        validated: A validated TelemetrySchema instance.

    Returns:
        Dictionary containing normalized telemetry data ready for
        TelemetryEvent.payload column.
    """
    # Build the normalized payload preserving all validated fields
    payload = {
        "timestamp": validated.timestamp.isoformat(),
        "event_type": validated.event_type,
        "source": validated.source,
    }

    # Add structured fields if present
    if validated.host is not None:
        payload["host"] = validated.host.model_dump(exclude_none=True)
    if validated.user is not None:
        payload["user"] = validated.user.model_dump(exclude_none=True)
    if validated.process is not None:
        payload["process"] = validated.process.model_dump(exclude_none=True)
    if validated.network is not None:
        payload["network"] = validated.network.model_dump(exclude_none=True)
    if validated.file is not None:
        payload["file"] = validated.file.model_dump(exclude_none=True)
    if validated.metadata is not None:
        metadata_dump = validated.metadata.model_dump(exclude_none=True)
        # Convert UUID to string if present
        if "correlation_id" in metadata_dump and metadata_dump["correlation_id"] is not None:
            metadata_dump["correlation_id"] = str(metadata_dump["correlation_id"])
        payload["metadata"] = metadata_dump
    if validated.raw is not None:
        payload["raw"] = validated.raw

    return payload


def create_telemetry_event(validated: TelemetrySchema) -> "TelemetryEvent":
    """Create a TelemetryEvent database model from validated telemetry.

    Args:
        validated: A validated TelemetrySchema instance.

    Returns:
        Unsaved TelemetryEvent instance ready for database session.
    """
    from sentinelforge.models import TelemetryEvent

    payload = normalize_telemetry(validated)

    event = TelemetryEvent(
        source=validated.source,
        event_type=validated.event_type,
        payload=payload,
        # received_at will use the default (server-side time)
        # processed defaults to False
    )
    return event