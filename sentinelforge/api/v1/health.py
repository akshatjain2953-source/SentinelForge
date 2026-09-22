"""Health check endpoint for SentinelForge API v1."""
from flask import Blueprint, current_app, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint confirming API status and basic service metadata."""
    payload = {
        "status": "healthy",
        "service": current_app.config.get("SERVICE_NAME", "sentinelforge-api"),
        "version": current_app.config.get("API_VERSION", "v1"),
        "environment": current_app.config.get("ENV", "development"),
    }
    return jsonify(payload), 200
