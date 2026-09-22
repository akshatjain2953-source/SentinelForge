"""API v1 Blueprint definition."""
from flask import Blueprint
from sentinelforge.api.v1.health import health_bp

api_v1_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")
api_v1_bp.register_blueprint(health_bp)
