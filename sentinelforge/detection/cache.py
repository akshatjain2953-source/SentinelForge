"""In-memory detection rule cache for SentinelForge Detection-as-Code."""

import logging
import re
import threading
from collections import defaultdict
from typing import Any, Optional

from sentinelforge.detection.loader import load_rules
from sentinelforge.config import Config

logger = logging.getLogger(__name__)


_EVENT_TYPE_PATTERN = re.compile(r"event_type\s*[=!<>]\s*['\"]([^'\"]+)['\"]")


def _extract_event_type(query: str) -> Optional[str]:
    """Extract event_type from a SQL query if present.

    Looks for patterns like: event_type = 'value', event_type != 'value', etc.
    """
    if not query:
        return None
    match = _EVENT_TYPE_PATTERN.search(query)
    if match:
        return match.group(1)
    return None


class RuleCache:
    """Thread-safe in-memory cache for detection rules."""

    def __init__(self, rules_dir: Optional[str] = None):
        """Initialize the rule cache.

        Args:
            rules_dir: Optional path to rules directory. If None, uses Config.RULES_DIR.
        """
        self._rules_dir = rules_dir or Config.RULES_DIR
        self._cache: dict[str, dict[str, Any]] = {}
        self._enabled_cache: dict[str, dict[str, Any]] = {}
        self._event_type_index: defaultdict[str, set[str]] = defaultdict(set)
        self._no_event_type_rules: set[str] = set()
        self._lock = threading.RLock()
        self._loaded = False

    def load(self) -> int:
        """Load rules from the configured directory into the cache.

        Returns:
            Number of rules loaded.
        """
        with self._lock:
            rules = load_rules(self._rules_dir)
            self._cache = {rule["id"]: rule for rule in rules}
            self._enabled_cache = {
                rule_id: rule for rule_id, rule in self._cache.items() if rule.get("enabled", True)
            }
            # Build event_type index for enabled rules
            self._event_type_index.clear()
            self._no_event_type_rules.clear()
            for rule_id, rule in self._enabled_cache.items():
                event_type = rule.get("event_type")
                if not event_type:
                    # Try to extract from query for backward compatibility
                    event_type = _extract_event_type(rule.get("query", ""))
                if event_type:
                    self._event_type_index[event_type].add(rule_id)
                else:
                    # Rule without event_type - applies to all event types
                    self._no_event_type_rules.add(rule_id)
            self._loaded = True
            logger.info("Rule cache loaded with %d rules (%d enabled)", len(self._cache), len(self._enabled_cache))
            return len(self._cache)

    def get(self, rule_id: str) -> Optional[dict[str, Any]]:
        """Get a rule by its ID.

        Args:
            rule_id: The rule ID to look up.

        Returns:
            The rule dictionary if found, None otherwise.
        """
        with self._lock:
            return self._cache.get(rule_id)

    def get_all(self) -> list[dict[str, Any]]:
        """Get all rules in the cache.

        Returns:
            List of all rule dictionaries.
        """
        with self._lock:
            return list(self._cache.values())

    def get_enabled(self) -> list[dict[str, Any]]:
        """Get all enabled rules in the cache.

        Returns:
            List of enabled rule dictionaries.
        """
        with self._lock:
            return list(self._enabled_cache.values())

    def get_enabled_by_event_type(self, event_type: str) -> list[dict[str, Any]]:
        """Get enabled rules for a specific event type.

        Args:
            event_type: The event type to filter rules by.

        Returns:
            List of enabled rule dictionaries matching the event type.
            Rules without explicit event_type are included (backward compatibility).
        """
        with self._lock:
            rule_ids = self._event_type_index.get(event_type, set())
            # Also include rules without explicit event_type (backward compatibility)
            rule_ids |= self._no_event_type_rules
            return [self._enabled_cache[rule_id] for rule_id in rule_ids if rule_id in self._enabled_cache]

    def reload(self) -> int:
        """Reload rules from the configured directory, replacing the cache atomically.

        Returns:
            Number of rules loaded after reload.
        """
        with self._lock:
            rules = load_rules(self._rules_dir)
            new_cache = {rule["id"]: rule for rule in rules}
            new_enabled_cache = {
                rule_id: rule for rule_id, rule in new_cache.items() if rule.get("enabled", True)
            }
            # Rebuild event_type index
            new_event_type_index: defaultdict[str, set[str]] = defaultdict(set)
            new_no_event_type_rules: set[str] = set()
            for rule_id, rule in new_enabled_cache.items():
                event_type = rule.get("event_type")
                if not event_type:
                    # Try to extract from query for backward compatibility
                    event_type = _extract_event_type(rule.get("query", ""))
                if event_type:
                    new_event_type_index[event_type].add(rule_id)
                else:
                    new_no_event_type_rules.add(rule_id)
            # Atomic replacement
            self._cache = new_cache
            self._enabled_cache = new_enabled_cache
            self._event_type_index = new_event_type_index
            self._no_event_type_rules = new_no_event_type_rules
            self._loaded = True
            logger.info("Rule cache reloaded with %d rules (%d enabled)", len(self._cache), len(self._enabled_cache))
            return len(self._cache)

    def is_loaded(self) -> bool:
        """Check if the cache has been loaded."""
        with self._lock:
            return self._loaded

    def __len__(self) -> int:
        """Return the number of rules in the cache."""
        with self._lock:
            return len(self._cache)