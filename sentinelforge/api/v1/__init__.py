"""API v1 Blueprint definition."""
from flask import Blueprint
from sentinelforge.api.v1.health import health_bp
from sentinelforge.api.v1.telemetry import telemetry_bp
from sentinelforge.api.v1.rules import rules_bp

api_v1_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")
api_v1_bp.register_blueprint(health_bp)
api_v1_bp.register_blueprint(telemetry_bp)
api_v1_bp.register_blueprint(rules_bp)
