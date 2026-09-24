"""DetectionRule synchronization service for SentinelForge.

Synchronizes validated YAML detection rules into the DetectionRule database table.
"""
import logging
from typing import Any, Optional

from sentinelforge.database import db
from sentinelforge.models import DetectionRule

logger = logging.getLogger(__name__)


class DetectionRuleSync:
    """Service for synchronizing validated YAML rules to the DetectionRule table."""

    def __init__(self, session=None):
        """Initialize the sync service.

        Args:
            session: Optional database session. If None, uses db.session.
        """
        self._session = session or db.session

    def sync(self, rules: list[dict[str, Any]]) -> int:
        """Synchronize a list of validated rules to the database.

        Args:
            rules: List of validated rule dictionaries from YAML loader/cache.

        Returns:
            Number of rules synchronized.

        Raises:
            Exception: If synchronization fails, the transaction is rolled back.
        """
        if not rules:
            logger.info("No rules to synchronize")
            return 0

        try:
            synced_count = 0
            for rule_data in rules:
                self._sync_single_rule(rule_data)
                synced_count += 1

            self._session.commit()
            logger.info("Synchronized %d detection rules to database", synced_count)
            return synced_count

        except Exception as e:
            self._session.rollback()
            logger.exception("Failed to synchronize detection rules: %s", e)
            raise

    def _sync_single_rule(self, rule_data: dict[str, Any]) -> None:
        """Synchronize a single rule to the database.

        Args:
            rule_data: Validated rule dictionary.
        """
        rule_id = rule_data["id"]

        # Look up existing rule by YAML rule_id
        db_rule = self._session.query(DetectionRule).filter_by(rule_id=rule_id).first()

        if db_rule:
            # Update existing rule
            self._update_rule(db_rule, rule_data)
            logger.debug("Updated DetectionRule: %s", rule_id)
        else:
            # Insert new rule
            self._insert_rule(rule_data)
            logger.debug("Inserted DetectionRule: %s", rule_id)

    def _insert_rule(self, rule_data: dict[str, Any]) -> DetectionRule:
        """Insert a new DetectionRule from validated rule data.

        Args:
            rule_data: Validated rule dictionary.

        Returns:
            The created DetectionRule instance.
        """
        db_rule = DetectionRule(
            rule_id=rule_data["id"],
            name=rule_data["name"],
            description=rule_data.get("description"),
            severity=rule_data["severity"],
            version=rule_data["version"],
            enabled=rule_data.get("enabled", True),
            author=rule_data.get("author"),
            format=rule_data.get("format", "yaml"),
            query=rule_data["query"],
            tags=rule_data.get("tags"),
            attck_techniques=rule_data.get("attck_techniques"),
            test_cases=rule_data.get("test_cases"),
        )
        self._session.add(db_rule)
        return db_rule

    def _update_rule(self, db_rule: DetectionRule, rule_data: dict[str, Any]) -> None:
        """Update an existing DetectionRule from validated rule data.

        Args:
            db_rule: Existing DetectionRule instance.
            rule_data: Validated rule dictionary.
        """
        db_rule.name = rule_data["name"]
        db_rule.description = rule_data.get("description")
        db_rule.severity = rule_data["severity"]
        db_rule.version = rule_data["version"]
        db_rule.enabled = rule_data.get("enabled", True)
        db_rule.author = rule_data.get("author")
        db_rule.format = rule_data.get("format", "yaml")
        db_rule.query = rule_data["query"]
        db_rule.tags = rule_data.get("tags")
        db_rule.attck_techniques = rule_data.get("attck_techniques")
        db_rule.test_cases = rule_data.get("test_cases")


def sync_rules(rules: list[dict[str, Any]], session=None) -> int:
    """Convenience function to synchronize rules.

    Args:
        rules: List of validated rule dictionaries.
        session: Optional database session.

    Returns:
        Number of rules synchronized.

    Raises:
        Exception: If synchronization fails.
    """
    sync_service = DetectionRuleSync(session)
    return sync_service.sync(rules)