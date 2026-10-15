"""Detection worker for asynchronous telemetry processing."""
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from flask import Flask
from sqlalchemy import text

from sentinelforge.database import db
from sentinelforge.detection.cache import RuleCache
from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.models import TelemetryEvent

logger = logging.getLogger(__name__)


class DetectionWorker:
    """Background worker for processing telemetry events through detection engine."""

    def __init__(
        self,
        app: Flask,
        rule_cache: RuleCache,
        batch_size: Optional[int] = None,
        poll_interval: Optional[float] = None,
    ):
        """Initialize the detection worker.

        Args:
            app: Flask application instance.
            rule_cache: RuleCache instance for loading detection rules.
            batch_size: Number of events to process per batch. Defaults to config.
            poll_interval: Seconds to wait between polling. Defaults to config.
        """
        self.app = app
        self.rule_cache = rule_cache
        self.batch_size = batch_size or app.config.get("DETECTION_BATCH_SIZE", 100)
        self.poll_interval = poll_interval or app.config.get("DETECTION_POLL_INTERVAL", 1.0)
        self.engine = DetectionEngine(rule_cache)

        self._shutdown = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the worker thread."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                logger.warning("Worker already running")
                return

            self._shutdown.clear()
            self._thread = threading.Thread(target=self._run, daemon=False, name="DetectionWorker")
            self._thread.start()
            logger.info("Detection worker started")

    def stop(self, timeout: float = 30.0) -> bool:
        """Stop the worker gracefully.

        Args:
            timeout: Maximum seconds to wait for thread to finish.

        Returns:
            True if stopped cleanly, False if timed out.
        """
        logger.info("Stopping detection worker")
        self._shutdown.set()

        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                self._thread.join(timeout=timeout)
                if self._thread.is_alive():
                    logger.error("Worker did not stop within timeout")
                    return False

        logger.info("Detection worker stopped")
        return True

    def is_running(self) -> bool:
        """Check if worker is running."""
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        """Main worker loop."""
        # Initial stale claim recovery
        self._recover_stale_claims()

        while not self._shutdown.is_set():
            try:
                self._process_batch()
            except Exception:
                logger.exception("Worker batch error")

            # Wait for poll interval or shutdown
            self._shutdown.wait(self.poll_interval)

        # Final stale claim recovery on shutdown
        self._recover_stale_claims()
        logger.info("Worker loop exited")

    def _process_batch(self) -> None:
        """Process a batch of pending events."""
        with self.app.app_context():
            events = self._claim_events()
            if not events:
                return

            logger.debug("Processing batch of %d events", len(events))

            for event in events:
                try:
                    self._process_event(event)
                except Exception:
                    logger.exception("Failed to process event %d", event.id)
                    self._mark_failed(event.id)

    def _claim_events(self) -> List[TelemetryEvent]:
        """Atomically claim a batch of pending events.

        Returns:
            List of claimed TelemetryEvent objects.
        """
        from sqlalchemy import text

        if db.engine.dialect.name == "postgresql":
            # PostgreSQL: FOR UPDATE SKIP LOCKED
            claimed = db.session.execute(text("""
                UPDATE telemetry_events
                SET status = 'claimed', claim_count = claim_count + 1, updated_at = NOW()
                WHERE id IN (
                    SELECT id FROM telemetry_events
                    WHERE status = 'pending'
                    ORDER BY received_at
                    LIMIT :batch_size
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING id, source, event_type, payload, received_at, status, claim_count, updated_at
            """), {"batch_size": self.batch_size}).mappings().all()
        else:
            # SQLite: Atomic UPDATE with RETURNING
            claimed = db.session.execute(text("""
                UPDATE telemetry_events
                SET status = 'claimed', claim_count = claim_count + 1, updated_at = datetime('now')
                WHERE id IN (
                    SELECT id FROM telemetry_events
                    WHERE status = 'pending'
                    ORDER BY received_at
                    LIMIT :batch_size
                )
                RETURNING id, source, event_type, payload, received_at, status, claim_count, updated_at
            """), {"batch_size": self.batch_size}).mappings().all()

        db.session.commit()
        return [self._row_to_telemetry_event(row) for row in claimed]

    def _row_to_telemetry_event(self, row) -> TelemetryEvent:
        """Convert a database row to a TelemetryEvent object."""
        return TelemetryEvent(
            id=row["id"],
            source=row["source"],
            event_type=row["event_type"],
            payload=row["payload"],
            received_at=row["received_at"],
            status=row["status"],
            claim_count=row["claim_count"],
            updated_at=row["updated_at"],
        )

    def _process_event(self, event: TelemetryEvent) -> None:
        """Process a single telemetry event through the detection engine."""
        try:
            results = self.engine.evaluate(event, persist=True)
        except Exception:
            logger.exception("Engine evaluation failed for event %d", event.id)
            self._mark_failed(event.id)
            return

        # Determine final event status
        final_status = self._determine_event_status(event, results)

        if final_status == "completed":
            self._mark_completed(event.id)
        else:
            self._mark_failed(event.id)

    def _determine_event_status(self, event: TelemetryEvent, results) -> str:
        """Determine final event status from detection results."""
        statuses = {r.persistence_status for r in results}
        if "failed" in statuses:
            return "failed"
        if all(s in ("success", "skipped_missing_rule", "none") for s in statuses):
            return "completed"
        return "failed"

    def _mark_completed(self, event_id: int) -> None:
        """Mark event as completed."""
        from sentinelforge.models import TelemetryEvent
        TelemetryEvent.query.filter_by(id=event_id).update({
            "status": "completed",
            "updated_at": datetime.now(timezone.utc),
        })
        db.session.commit()

    def _mark_failed(self, event_id: int) -> None:
        """Mark event as failed."""
        from sentinelforge.models import TelemetryEvent
        TelemetryEvent.query.filter_by(id=event_id).update({
            "status": "failed",
            "updated_at": datetime.now(timezone.utc),
        })
        db.session.commit()

    def _recover_stale_claims(self, max_age_seconds: int = 300) -> None:
        """Recover events stuck in 'claimed' state (worker crashed mid-processing)."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)

        try:
            if db.engine.dialect.name == "postgresql":
                db.session.execute(text("""
                    UPDATE telemetry_events
                    SET status = 'pending', claim_count = claim_count + 1, updated_at = NOW()
                    WHERE status = 'claimed' AND updated_at < :cutoff
                """), {"cutoff": cutoff})
            else:
                TelemetryEvent.query.filter(
                    TelemetryEvent.status == "claimed",
                    TelemetryEvent.updated_at < cutoff
                ).update({
                    "status": "pending",
                    "claim_count": TelemetryEvent.claim_count + 1
                })
            db.session.commit()
            logger.info("Recovered stale claims")
        except Exception:
            logger.exception("Failed to recover stale claims")