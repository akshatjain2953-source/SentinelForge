"""Tests for the detection rules API endpoints."""
import tempfile
import os
import unittest
from sentinelforge import create_app
from sentinelforge.detection.cache import RuleCache
from sentinelforge.detection.loader import load_rules
from sentinelforge.detection.schema import DetectionRuleSchema


class RulesAPITests(unittest.TestCase):
    """Tests for the detection rules API endpoints."""

    def _make_valid_rule(self, rule_id: str = "test-rule", name: str = "Test Rule") -> str:
        """Return a minimal valid rule YAML string."""
        return f"""id: "{rule_id}"
name: "{name}"
severity: "high"
enabled: true
version: "1.0.0"
query: "SELECT 1"
"""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.rules_dir = self.tmpdir.name
        
        # Create app with temp rules directory
        self.app = create_app("testing")
        self.app.config["RULES_DIR"] = self.rules_dir
        self.client = self.app.test_client()
        
        # Initialize rule cache with the temp directory
        with self.app.app_context():
            from sentinelforge.detection.cache import RuleCache
            self.app.extensions["rule_cache"] = RuleCache(self.rules_dir)
            self.app.extensions["rule_cache"].load()

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write_rule(self, filename: str, content: str = None, rule_id: str = None, name: str = None):
        """Helper to write a rule file."""
        path = os.path.join(self.rules_dir, filename)
        if content is None:
            content = f"""id: "{filename.replace('.yaml', '').replace('.yml', '')}"
name: "{filename.replace('.yaml', '').replace('.yml', '')}"
severity: "high"
enabled: true
version: "1.0.0"
query: "SELECT 1"
"""
        with open(path, "w") as f:
            f.write(content)

    def test_get_rules_returns_loaded_rules(self):
        """Test GET /api/v1/rules returns loaded rules."""
        self._write_rule("rule1.yaml", """id: "rule-1"
name: "Rule 1"
severity: "high"
enabled: true
version: "1.0.0"
query: "SELECT 1"
""")
        self._write_rule("rule2.yaml", content="""id: "rule-2"
name: "Rule 2"
severity: "medium"
enabled: true
version: "1.0.0"
query: "SELECT 2"
""")

        with self.app.app_context():
            cache = self.app.extensions["rule_cache"]
            cache.load()

        response = self.client.get("/api/v1/rules")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["count"], 2)
        self.assertEqual(len(data["data"]), 2)
        ids = {r["id"] for r in data["data"]}
        self.assertEqual(ids, {"rule-1", "rule-2"})

    def test_get_single_rule(self):
        """Test GET /api/v1/rules/<rule_id> returns a single rule."""
        self._write_rule("rule.yaml", """id: "test-rule"
name: "Test Rule"
severity: "high"
enabled: true
version: "1.0.0"
query: "SELECT 1"
""")

        with self.app.app_context():
            cache = self.app.extensions["rule_cache"]
            cache.load()

        response = self.client.get("/api/v1/rules/test-rule")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["data"]["id"], "test-rule")
        self.assertEqual(data["data"]["name"], "Test Rule")

    def test_get_unknown_rule_returns_404(self):
        """Test GET /api/v1/rules/<rule_id> returns 404 for unknown rule."""
        response = self.client.get("/api/v1/rules/nonexistent")
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["error"]["code"], 404)

    def test_post_reload_refreshes_cache(self):
        """Test POST /api/v1/rules/reload refreshes the cache."""
        self._write_rule("rule1.yaml", """id: "rule-1"
name: "Rule 1"
severity: "high"
enabled: true
version: "1.0.0"
query: "SELECT 1"
""")

        with self.app.app_context():
            cache = self.app.extensions["rule_cache"]
            cache.load()

        response = self.client.post("/api/v1/rules/reload")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("count", data)

    def test_api_does_not_expose_internal_errors(self):
        """Test API does not expose internal errors or stack traces."""
        response = self.client.post("/api/v1/rules/reload")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        response_text = str(response.get_json())
        self.assertNotIn("traceback", response_text.lower())
        self.assertNotIn("trace", response_text.lower())


if __name__ == "__main__":
    unittest.main()