"""Detection Engine for SentinelForge.

Evaluates normalized telemetry events against detection rules using
SQLite-based query evaluation for safe SQL-like query execution.
"""
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

from sentinelforge.database import db
from sentinelforge.detection.cache import RuleCache
from sentinelforge.models import DetectionRule, DetectionExecution, TelemetryEvent, Alert

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result of evaluating a single rule against a telemetry event."""
    rule_id: str
    rule_name: str
    matched: bool
    error: Optional[str] = None
    execution_time_ms: int = 0
    persistence_status: str = "none"


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

    def evaluate(
        self, telemetry_event: TelemetryEvent, persist: bool = True
    ) -> list[DetectionResult]:
        """Evaluate a telemetry event against enabled detection rules matching its event type.

        Args:
            telemetry_event: Normalized telemetry event to evaluate.
            persist: Whether to persist matched results to database (DetectionExecution + Alert).
                    Requires an active Flask application context.

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

                if matched:
                    logger.info(
                        "Rule matched: %s (%s) for event %s",
                        rule_data.get("name"),
                        rule_data.get("id"),
                        telemetry_event.id,
                    )
                    if persist:
                        persistence_status = self._persist_match(rule_data, telemetry_event, execution_time_ms)
                    else:
                        persistence_status = "none"
                else:
                    logger.debug(
                        "Rule did not match: %s (%s) for event %s",
                        rule_data.get("name"),
                        rule_data.get("id"),
                        telemetry_event.id,
                    )
                    persistence_status = "none"

                result = DetectionResult(
                    rule_id=rule_data["id"],
                    rule_name=rule_data.get("name", ""),
                    matched=matched,
                    execution_time_ms=execution_time_ms,
                    persistence_status=persistence_status,
                )
                results.append(result)

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
                    persistence_status="none",
                ))

        return results

    def _persist_match(
        self,
        rule_data: dict[str, Any],
        telemetry_event: TelemetryEvent,
        execution_time_ms: int,
    ) -> str:
        """Persist a matched detection result as DetectionExecution and Alert.

        Args:
            rule_data: The rule dictionary from cache.
            telemetry_event: The telemetry event that was evaluated.
            execution_time_ms: Rule evaluation execution time in milliseconds.

        Returns:
            Persistence status: "success", "failed", or "skipped_missing_rule".
        """
        try:
            # Look up the detection rule in the database by YAML rule_id
            db_rule = db.session.query(DetectionRule).filter_by(
                rule_id=rule_data["id"]
            ).first()

            if not db_rule:
                logger.warning(
                    "Detection rule %s not found in database, skipping persistence",
                    rule_data["id"],
                )
                return "skipped_missing_rule"

            # Idempotency check: see if DetectionExecution already exists for this rule+event
            existing_execution = db.session.query(DetectionExecution).filter_by(
                detection_rule_id=db_rule.id,
                telemetry_event_id=telemetry_event.id,
            ).first()

            if existing_execution:
                logger.info(
                    "DetectionExecution already exists for rule %s and event %s (execution_id=%d), skipping duplicate",
                    rule_data["id"],
                    telemetry_event.id,
                    existing_execution.id,
                )
                return "success"

            # Create DetectionExecution
            execution = DetectionExecution(
                detection_rule_id=db_rule.id,
                telemetry_event_id=telemetry_event.id,
                matched=True,
                execution_time_ms=execution_time_ms,
            )
            db.session.add(execution)
            db.session.flush()  # Get execution ID

            # Create Alert
            alert = Alert(
                detection_rule_id=db_rule.id,
                detection_execution_id=execution.id,
                severity=db_rule.severity,
                status="new",
                title=f"{db_rule.name}: {rule_data.get('name', 'Detection Match')}",
                description=db_rule.description,
                evidence=self._build_evidence(telemetry_event, rule_data),
            )
            db.session.add(alert)

            # Associate ATT&CK techniques if present
            attck_techniques = db_rule.attck_techniques or []
            if attck_techniques:
                self._associate_attck_techniques(alert, attck_techniques)

            db.session.commit()
            logger.info(
                "Persisted DetectionExecution %d and Alert %d for rule %s",
                execution.id,
                alert.id,
                rule_data["id"],
            )
            return "success"

        except Exception as e:
            db.session.rollback()
            logger.exception(
                "Failed to persist detection match for rule %s: %s",
                rule_data.get("id"),
                e,
            )
            # Don't raise - persistence failure shouldn't affect evaluation results
            return "failed"

    def _build_evidence(
        self, telemetry_event: TelemetryEvent, rule_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Build evidence dictionary from telemetry event and rule.

        Args:
            telemetry_event: The telemetry event that triggered the match.
            rule_data: The rule that matched.

        Returns:
            Dictionary containing evidence for the alert.
        """
        payload = telemetry_event.payload or {}
        evidence = {
            "telemetry_event_id": telemetry_event.id,
            "event_type": telemetry_event.event_type,
            "source": telemetry_event.source,
            "timestamp": telemetry_event.received_at.isoformat()
            if telemetry_event.received_at
            else None,
            "rule_query": rule_data.get("query", ""),
            "matched_fields": {},
        }

        # Add relevant payload fields as evidence
        for key, value in payload.items():
            if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
                evidence["matched_fields"][key] = value

        return evidence

    def _associate_attck_techniques(
        self, alert: Alert, technique_ids: list[str]
    ) -> None:
        """Associate ATT&CK techniques with the alert.

        Args:
            alert: The alert to associate techniques with.
            technique_ids: List of ATT&CK technique IDs (e.g., ["T1059", "T1059.001"]).
        """
        from sentinelforge.models import AttckTechnique

        for tech_id in technique_ids:
            technique = db.session.query(AttckTechnique).filter_by(
                technique_id=tech_id
            ).first()
            if technique:
                alert.attck_techniques.append(technique)
            else:
                logger.warning(
                    "ATT&CK technique %s not found in database, skipping",
                    tech_id,
                )

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
        payload = telemetry_event.payload or {}
        row = {
            "event_type": telemetry_event.event_type,
            "source": telemetry_event.source,
            "timestamp": telemetry_event.received_at.isoformat() if telemetry_event.received_at else None,
            "processed": telemetry_event.status == "completed",
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