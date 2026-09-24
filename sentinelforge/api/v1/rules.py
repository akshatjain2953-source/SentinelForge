"""Detection rules API endpoints for SentinelForge API v1."""
import logging
from flask import Blueprint, jsonify, request, current_app
from sentinelforge.detection.cache import RuleCache
from sentinelforge.detection.sync import sync_rules

rules_bp = Blueprint("rules", __name__)

logger = logging.getLogger(__name__)


def get_rule_cache():
    """Get or create the rule cache from the current app context."""
    if "rule_cache" not in current_app.extensions:
        current_app.extensions["rule_cache"] = RuleCache(current_app.config.get("RULES_DIR"))
    else:
        # Update rules_dir in case config changed (e.g., for tests)
        current_app.extensions["rule_cache"]._rules_dir = current_app.config.get("RULES_DIR")
    return current_app.extensions["rule_cache"]


@rules_bp.route("/rules", methods=["GET"])
def list_rules():
    """List all detection rules.

    Returns:
        JSON response with list of all loaded detection rules.
    """
    cache = get_rule_cache()
    rules = cache.get_all()
    return jsonify({
        "status": "success",
        "data": rules,
        "count": len(rules)
    })


@rules_bp.route("/rules/<rule_id>", methods=["GET"])
def get_rule(rule_id: str):
    """Get a specific detection rule by ID.

    Args:
        rule_id: The ID of the rule to retrieve.

    Returns:
        JSON response with the rule data, or 404 if not found.
    """
    cache = get_rule_cache()
    rule = cache.get(rule_id)

    if rule is None:
        return jsonify({
            "status": "error",
            "error": {
                "code": 404,
                "name": "Not Found",
                "message": f"Rule '{rule_id}' not found"
            }
        }), 404

    return jsonify({
        "status": "success",
        "data": rule
    })


@rules_bp.route("/rules/reload", methods=["POST"])
def reload_rules():
    """Reload detection rules from the configured directory.

    Returns:
        JSON response with reload status and rule count.
    """
    cache = get_rule_cache()

    try:
        count = cache.reload()
        # Synchronize validated rules to DetectionRule database table
        validated_rules = cache.get_enabled()
        db_sync_status = "success"
        if validated_rules:
            try:
                sync_rules(validated_rules)
            except Exception as e:
                logger.exception("DetectionRule DB sync failed during reload: %s", e)
                db_sync_status = "failed"
                # Cache reload succeeded, but DB sync failed
                # Return partial success - do NOT expose DB internals
                return jsonify({
                    "status": "error",
                    "message": f"Reloaded {count} rules",
                    "count": count,
                    "cache_reloaded": True,
                    "db_sync": db_sync_status
                }), 500

        return jsonify({
            "status": "success",
            "message": f"Reloaded {count} rules",
            "count": count,
            "cache_reloaded": True,
            "db_sync": db_sync_status
        })
    except Exception as e:
        # Log the error internally but don't expose details
        logger.exception("Failed to reload rules")
        return jsonify({
            "status": "error",
            "error": {
                "code": 500,
                "name": "Internal Server Error",
                "message": "Failed to reload rules"
            }
        }), 500