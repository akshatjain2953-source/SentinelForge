"""Detection Engine for SentinelForge.

Evaluates normalized telemetry events against detection rules using
SQLite-based query evaluation for safe SQL-like query execution.
"""
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

from sentinelforge.detection.cache import RuleCache
from sentinelforge.models import DetectionRule, DetectionExecution, TelemetryEvent

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result of evaluating a single rule against a telemetry event."""
    rule_id: str
    rule_name: str
    matched: bool
    error: Optional[str] = None
    execution_time_ms: int = 0


class DetectionEngine:
    """Core detection engine for evaluating telemetry against detection rules.

    Uses SQLite in-memory database for safe SQL query evaluation against
    normalized telemetry events. No arbitrary code execution.
    """

    def __init__(self, rule_cache: RuleCache):
        """Initialize the detection engine with a rule cache.

        Args:
            rule_cache: RuleCache instance containing loaded detection rules.
        """
        self.rule_cache = rule_cache

    def evaluate(self, telemetry_event: TelemetryEvent) -> list[DetectionResult]:
        """Evaluate a telemetry event against enabled detection rules matching its event type.

        Args:
            telemetry_event: Normalized telemetry event to evaluate.

        Returns:
            List of DetectionResult for each evaluated rule.
        """
        if not self.rule_cache.is_loaded():
            logger.warning("Rule cache not loaded, attempting to load")
            self.rule_cache.load()

        # Filter rules by event_type for efficiency
        event_type = telemetry_event.event_type
        enabled_rules = self.rule_cache.get_enabled_by_event_type(event_type)
        results = []

        for rule_data in enabled_rules:
            start_time = time.perf_counter()
            try:
                matched = self._evaluate_rule(rule_data, telemetry_event)
                execution_time_ms = int((time.perf_counter() - start_time) * 1000)

                result = DetectionResult(
                    rule_id=rule_data["id"],
                    rule_name=rule_data.get("name", ""),
                    matched=matched,
                    execution_time_ms=execution_time_ms,
                )
                results.append(result)

                if matched:
                    logger.info(
                        "Rule matched: %s (%s) for event %s",
                        rule_data.get("name"),
                        rule_data.get("id"),
                        telemetry_event.id,
                    )
                else:
                    logger.debug(
                        "Rule did not match: %s (%s) for event %s",
                        rule_data.get("name"),
                        rule_data.get("id"),
                        telemetry_event.id,
                    )

            except Exception as e:
                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                logger.exception(
                    "Error evaluating rule %s (%s): %s",
                    rule_data.get("name"),
                    rule_data.get("id"),
                    e,
                )
                results.append(DetectionResult(
                    rule_id=rule_data.get("id", "unknown"),
                    rule_name=rule_data.get("name", "unknown"),
                    matched=False,
                    error=str(e),
                    execution_time_ms=execution_time_ms,
                ))

        return results

    def _evaluate_rule(self, rule_data: dict[str, Any], telemetry_event: TelemetryEvent) -> bool:
        """Evaluate a single rule against a telemetry event.

        Args:
            rule_data: Validated rule dictionary from cache.
            telemetry_event: Normalized telemetry event to evaluate.

        Returns:
            True if the rule matches, False otherwise.
        """
        query = rule_data.get("query", "").strip()
        if not query:
            logger.warning("Rule %s has empty query", rule_data.get("id"))
            return False

        # Build the telemetry row as a dictionary for SQLite evaluation
        telemetry_row = self._build_telemetry_row(telemetry_event)

        try:
            return self._execute_query(query, telemetry_row)
        except Exception as e:
            logger.warning("Query evaluation failed for rule %s: %s", rule_data.get("id"), e)
            raise

    def _build_telemetry_row(self, telemetry_event: TelemetryEvent) -> dict[str, Any]:
        """Build a flat dictionary representation of the telemetry event for SQL evaluation.

        Args:
            telemetry_event: Normalized telemetry event.

        Returns:
            Dictionary with flattened telemetry fields suitable for SQL evaluation.
            Nested dicts are converted to JSON strings.
        """
        import json

        payload = telemetry_event.payload or {}
        row = {
            "event_type": telemetry_event.event_type,
            "source": telemetry_event.source,
            "timestamp": telemetry_event.received_at.isoformat() if telemetry_event.received_at else None,
            "processed": telemetry_event.processed,
        }

        # Add payload fields (these come from the normalized payload)
        if isinstance(payload, dict):
            for key, value in payload.items():
                if key not in row:  # Don't override base fields
                    # Convert nested dicts/lists to JSON strings for SQLite compatibility
                    if isinstance(value, (dict, list)):
                        row[key] = json.dumps(value)
                    else:
                        row[key] = value

        return row

    def _execute_query(self, query: str, telemetry_row: dict[str, Any]) -> bool:
        """Execute a SQL-like query against the telemetry row using SQLite.

        Args:
            query: SQL query string (e.g., "SELECT * FROM telemetry WHERE event_type = 'process_creation'").
            telemetry_row: Dictionary representing the telemetry event row.

        Returns:
            True if query returns any rows (match), False otherwise.
        """
        import sqlite3

        # Create in-memory SQLite database
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row

        try:
            cursor = conn.cursor()

            # Create table and insert the telemetry row
            columns = list(telemetry_row.keys())
            placeholders = ", ".join(["?"] * len(telemetry_row))
            columns_str = ", ".join([f'"{col}"' for col in telemetry_row.keys()])
            column_defs = ", ".join([f'"{col}" TEXT' for col in telemetry_row.keys()])

            # Create table and insert the telemetry row
            cursor.execute(f'CREATE TABLE telemetry ({column_defs})')
            cursor.execute(
                f'INSERT INTO telemetry ({columns_str}) VALUES ({placeholders})',
                list(telemetry_row.values())
            )

            # Execute the rule query
            cursor.execute(query)
            rows = cursor.fetchall()

            return len(rows) > 0

        except sqlite3.Error as e:
            logger.warning("SQLite error during query evaluation: %s", e)
            raise
        finally:
            conn.close()


# Export
__all__ = ["DetectionEngine", "DetectionResult"]