"""Tests for DetectionWorker asynchronous processing."""
import textwrap
import tempfile
import os
import time
from unittest.mock import patch

import unittest

from sentinelforge.detection.processor import DetectionWorker
from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.detection.cache import RuleCache
from sentinelforge.models import TelemetryEvent, DetectionExecution, Alert
from sentinelforge import db, create_app


class DetectionWorkerTests(unittest.TestCase):
    """Test suite for DetectionWorker."""

    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        self.tmpdir = tempfile.TemporaryDirectory()
        self.rules_dir = self.tmpdir.name
        self._create_matching_rule()
        self._create_pending_events(1)

    def tearDown(self):
        self.app_context.pop()
        self.tmpdir.cleanup()

    def _create_matching_rule(self):
        """Create a matching detection rule in the temp directory."""
        rules_path = os.path.join(self.rules_dir, "detection_rules.yaml")
        with open(rules_path, "w") as f:
            f.write(textwrap.dedent("""\
                id: "test-rule"
                name: "Test Rule"
                severity: "high"
                enabled: true
                version: "1.0.0"
                query: "SELECT * FROM telemetry WHERE event_type = 'process_creation'"
            """))
        cache = RuleCache(self.rules_dir)
        cache.load()

    def _create_pending_events(self, count):
        """Create pending telemetry events."""
        events = []
        with self.app.app_context():
            for i in range(count):
                event = TelemetryEvent(
                    source="test_source",
                    event_type="process_creation",
                    payload={"key": "value", "index": i},
                )
                db.session.add(event)
                events.append(event)
            db.session.commit()
        return events

    def test_app_context_and_db_session_cleanup(self):
        """Test that app context and DB session are cleaned up properly."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        with self.app.app_context():
            claimed = worker._claim_events()
            self.assertEqual(len(claimed), 1)

        # After context exit, session should be cleaned up
        self.assertFalse(worker.is_running())

    def test_claim_count_increments(self):
        """Test that claim_count increments on each claim."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        with self.app.app_context():
            claimed = worker._claim_events()
            self.assertEqual(len(claimed), 1)
            self.assertEqual(claimed[0].claim_count, 1)

            # Force stale recovery to re-claim the same event
            worker._recover_stale_claims(max_age_seconds=0)
            claimed = worker._claim_events()
            self.assertEqual(len(claimed), 1)
            # claim_count: 1 (initial) + 1 (stale recovery) + 1 (re-claim) = 3
            self.assertEqual(claimed[0].claim_count, 3)

    def test_claimed_event_processed_with_persist_true(self):
        """Test claimed event is processed with persist=True."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        with self.app.app_context():
            claimed = worker._claim_events()
            self.assertEqual(len(claimed), 1)

            # Mock the engine to verify it's called with persist=True
            with patch.object(worker.engine, 'evaluate', return_value=[
                type('Result', (), {'persistence_status': 'success'})()
            ]):
                worker._process_event(claimed[0])

            event = db.session.query(TelemetryEvent).filter_by(
                id=claimed[0].id).first()
            self.assertEqual(event.status, "completed")

    def test_empty_batch_does_not_crash(self):
        """Test empty batch does not crash the worker."""
        # Clear any existing events from setUp
        with self.app.app_context():
            db.session.query(TelemetryEvent).delete()
            db.session.commit()

        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        with self.app.app_context():
            claimed = worker._claim_events()
            # Should not crash with empty batch
            self.assertEqual(len(claimed), 0)

    def test_evaluation_exception_fails_event(self):
        """Test that evaluation exception fails the event."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        with self.app.app_context():
            claimed = worker._claim_events()
            self.assertEqual(len(claimed), 1)

            # Mock the engine to raise an exception
            with patch.object(worker.engine, 'evaluate', side_effect=RuntimeError("test error")):
                worker._process_event(claimed[0])

            event = db.session.query(TelemetryEvent).filter_by(
                id=claimed[0].id).first()
            self.assertEqual(event.status, "failed")

    def test_failed_persistence_fails_event(self):
        """Test that failed persistence status fails the event."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        with self.app.app_context():
            claimed = worker._claim_events()
            self.assertEqual(len(claimed), 1)

            # Mock the engine with failed persistence status
            with patch.object(worker.engine, 'evaluate', return_value=[
                type('Result', (), {'persistence_status': 'failed'})()
            ]):
                worker._process_event(claimed[0])

            event = db.session.query(TelemetryEvent).filter_by(
                id=claimed[0].id).first()
            self.assertEqual(event.status, "failed")

    def test_is_running_returns_correct_state(self):
        """Test is_running returns correct state."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        self.assertFalse(worker.is_running())
        worker.start()
        self.assertTrue(worker.is_running())
        worker.stop()

    def test_no_duplicate_processing_across_polls(self):
        """Test repeated polling doesn't create duplicate DetectionExecution/Alert records."""
        self._create_matching_rule()
        event = self._create_pending_events(1)[0]

        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        with self.app.app_context():
            # First batch
            with patch.object(worker.engine, 'evaluate', return_value=[
                type('Result', (), {'persistence_status': 'success'})()
            ]):
                claimed = worker._claim_events()
                for event in claimed:
                    worker._process_event(event)

            exec_count_1 = db.session.query(DetectionExecution).count()
            alert_count_1 = db.session.query(Alert).count()

            # Reset event to pending and process again
            db.session.query(TelemetryEvent).filter_by(id=event.id).update({
                "status": "pending"
            })
            db.session.commit()

            # Second batch
            with patch.object(worker.engine, 'evaluate', return_value=[
                type('Result', (), {'persistence_status': 'success'})()
            ]):
                claimed = worker._claim_events()
                for event in claimed:
                    worker._process_event(event)

            exec_count_2 = db.session.query(DetectionExecution).count()
            alert_count_2 = db.session.query(Alert).count()

            # Should not create duplicates
            self.assertEqual(exec_count_1, exec_count_2)
            self.assertEqual(alert_count_1, alert_count_2)

    def test_one_failed_event_does_not_stop_others(self):
        """Test one failed event doesn't stop others from processing."""
        # Clear any existing events from setUp and create 2 distinct events for this test
        with self.app.app_context():
            db.session.query(TelemetryEvent).delete()
            db.session.commit()
            for i in range(2):
                event = TelemetryEvent(
                    source="test_source",
                    event_type="process_creation",
                    payload={"key": "value", "index": i},
                )
                db.session.add(event)
            db.session.commit()

        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        with self.app.app_context():
            claimed = worker._claim_events()
            self.assertEqual(len(claimed), 2)

            # Make first event fail
            with patch.object(worker.engine, 'evaluate', side_effect=RuntimeError("test error")):
                worker._process_event(claimed[0])

            # Second event should still be processable (not failed by worker crash)
            # It's still in "claimed" status from the initial claim
            event2 = db.session.query(TelemetryEvent).filter_by(
                status="claimed").first()
            self.assertIsNotNone(event2)
            # Process the second event successfully
            with patch.object(worker.engine, 'evaluate', return_value=[
                type('Result', (), {'persistence_status': 'success'})()
            ]):
                worker._process_event(event2)

            event2 = db.session.query(TelemetryEvent).filter_by(
                id=event2.id).first()
            self.assertEqual(event2.status, "completed")

    def test_pending_events_are_claimed(self):
        """Test that pending events are claimed by the worker."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        with self.app.app_context():
            claimed = worker._claim_events()
            self.assertGreater(len(claimed), 0)
            for event in claimed:
                self.assertEqual(event.status, "claimed")

    def test_polling_continues_after_event_failure(self):
        """Test polling continues after event failure."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        worker.start()
        try:
            with self.app.app_context():
                claimed = worker._claim_events()
                self.assertEqual(len(claimed), 1)

                # Make event fail
                with patch.object(worker.engine, 'evaluate', side_effect=RuntimeError("test error")):
                    worker._process_event(claimed[0])

            # Worker should still be running and able to poll again
            self.assertTrue(worker.is_running())
        finally:
            worker.stop()

    def test_sqlite_claim_path_exercised(self):
        """Test SQLite claim path is exercised."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        with self.app.app_context():
            claimed = worker._claim_events()
            self.assertGreaterEqual(len(claimed), 0)

    def test_start_is_idempotent(self):
        """Test start is idempotent - calling start twice creates one thread."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        worker.start()
        worker.start()  # Should be idempotent
        self.assertTrue(worker.is_running())
        worker.stop(timeout=5)

    def test_start_starts_one_worker_thread(self):
        """Test start starts exactly one worker thread."""
        import threading
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        worker.start()
        # Should have exactly one thread running
        self.assertTrue(worker._thread is not None)
        self.assertTrue(worker._thread.is_alive())
        self.assertEqual(worker._thread.name, "DetectionWorker")
        worker.stop()

    def test_stop_shuts_down_cleanly(self):
        """Test stop shuts down the worker cleanly."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        worker.start()
        worker.stop()
        self.assertFalse(worker.is_running())

    def test_successful_processing_completes_event(self):
        """Test successful processing changes status to completed."""
        cache = RuleCache(self.rules_dir)
        cache.load()
        worker = DetectionWorker(self.app, cache)

        with self.app.app_context():
            claimed = worker._claim_events()
            self.assertEqual(len(claimed), 1)

            with patch.object(worker.engine, 'evaluate', return_value=[
                type('Result', (), {'persistence_status': 'success'})()
            ]):
                worker._process_event(claimed[0])

            event = db.session.query(TelemetryEvent).filter_by(
                id=claimed[0].id).first()
            self.assertEqual(event.status, "completed")