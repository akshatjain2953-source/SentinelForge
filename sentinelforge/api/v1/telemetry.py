"""Telemetry ingestion endpoint for SentinelForge API v1."""
from flask import Blueprint, jsonify, request
from sqlalchemy.exc import SQLAlchemyError
from sentinelforge.database import db
from sentinelforge.telemetry.schema import validate_telemetry, ValidationError
from sentinelforge.telemetry.normalize import create_telemetry_event

telemetry_bp = Blueprint("telemetry", __name__)


@telemetry_bp.route("/telemetry", methods=["POST"])
def ingest_telemetry():
    """Ingest a single telemetry event.

    Expects JSON payload conforming to TelemetrySchema.
    Validates, normalizes, and persists to database.
    Returns validation result or error details.
    """
    if not request.is_json:
        return jsonify({
            "status": "error",
            "error": {
                "code": 415,
                "name": "Unsupported Media Type",
                "message": "Content-Type must be application/json",
            },
            "path": request.path,
        }), 415

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({
            "status": "error",
            "error": {
                "code": 400,
                "name": "Bad Request",
                "message": "Request body must be valid JSON",
            },
            "path": request.path,
        }), 400

    try:
        validated = validate_telemetry(data)
    except ValidationError as e:
        return jsonify({
            "status": "error",
            "error": {
                "code": 422,
                "name": "Unprocessable Entity",
                "message": "Telemetry validation failed",
                "details": e.errors,
            },
            "path": request.path,
        }), 422

    # Create and persist the telemetry event
    event = create_telemetry_event(validated)
    db.session.add(event)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "error": {
                "code": 500,
                "name": "Internal Server Error",
                "message": "Failed to persist telemetry event",
            },
            "path": request.path,
        }), 500

    return jsonify({
        "status": "success",
        "message": "Telemetry accepted for processing",
        "data": {
            "id": event.id,
            "event_type": validated.event_type,
            "source": validated.source,
            "timestamp": validated.timestamp.isoformat(),
        },
    }), 202