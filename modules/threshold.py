# -*- coding: utf-8 -*-
"""
threshold.py - Sliding window brute force detection engine.

How it works:
  - Maintains a deque of timestamps per username and per source IP
  - On each new event, appends timestamp and purges entries older
    than window_seconds
  - If count within window exceeds threshold -> alert fires
  - Separate alert state prevents duplicate alerts per burst
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict


class SlidingWindowCounter:
    """
    Tracks event timestamps in a sliding time window per key.
    Thread-safe enough for single-threaded poll loops.
    """

    def __init__(self, threshold: int, window_seconds: int):
        self.threshold      = threshold
        self.window_seconds = window_seconds
        # key -> list of datetime timestamps within the window
        self._windows: Dict[str, list] = defaultdict(list)
        # keys that have already fired an alert (reset after quiet period)
        self._alerted: Dict[str, datetime] = {}

    def _purge_old(self, key: str, now: datetime):
        """Remove timestamps older than window_seconds from the deque."""
        cutoff = now - timedelta(seconds=self.window_seconds)
        self._windows[key] = [
            ts for ts in self._windows[key] if ts >= cutoff
        ]

    def add_event(self, key: str, timestamp: datetime) -> bool:
        """
        Register one event for the given key at the given timestamp.

        Returns:
            True  if this event pushed the key over threshold (fire alert)
            False otherwise
        """
        now = datetime.now()
        self._purge_old(key, now)
        self._windows[key].append(timestamp)

        count = len(self._windows[key])

        if count >= self.threshold:
            # Only alert once per burst - suppress until window clears
            last_alert = self._alerted.get(key)
            if last_alert is None or (now - last_alert).total_seconds() > self.window_seconds:
                self._alerted[key] = now
                return True

        return False

    def get_count(self, key: str) -> int:
        """Current event count within the window for a key."""
        self._purge_old(key, datetime.now())
        return len(self._windows[key])

    def reset(self, key: str):
        """Manually reset a key - call after an alert is handled."""
        self._windows.pop(key, None)
        self._alerted.pop(key, None)


class BruteForceDetector:
    """
    Wraps two SlidingWindowCounters:
      - one keyed by username
      - one keyed by source IP

    Feed it parsed 4625 events and it tells you when to alert.
    """

    def __init__(self, user_cfg: dict, ip_cfg: dict):
        """
        Args:
            user_cfg: {"count": N, "window_seconds": N}
            ip_cfg:   {"count": N, "window_seconds": N}
        """
        self.user_counter = SlidingWindowCounter(
            threshold      = user_cfg["count"],
            window_seconds = user_cfg["window_seconds"],
        )
        self.ip_counter = SlidingWindowCounter(
            threshold      = ip_cfg["count"],
            window_seconds = ip_cfg["window_seconds"],
        )

    def process_event(self, event: dict) -> List[dict]:
        """
        Feed one parsed 4625 event.
        Returns list of alert dicts (empty if no threshold crossed).
        Each alert dict has everything needed to write a CSV row or Teams card.
        """
        alerts    = []
        username  = event.get("username", "unknown")
        ip        = event.get("ip_address", "unknown")
        ts        = event.get("timestamp", datetime.now())

        # Check username threshold
        if self.user_counter.add_event(username, ts):
            alerts.append({
                "alert_type":   "USERNAME_BRUTE_FORCE",
                "key":          username,
                "key_type":     "username",
                "count":        self.user_counter.get_count(username),
                "threshold":    self.user_counter.threshold,
                "window_secs":  self.user_counter.window_seconds,
                "trigger_event":event,
                "detected_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity":     "HIGH",
            })

        # Check IP threshold
        if ip not in ("local", "", "unknown"):
            if self.ip_counter.add_event(ip, ts):
                alerts.append({
                    "alert_type":   "IP_BRUTE_FORCE",
                    "key":          ip,
                    "key_type":     "source_ip",
                    "count":        self.ip_counter.get_count(ip),
                    "threshold":    self.ip_counter.threshold,
                    "window_secs":  self.ip_counter.window_seconds,
                    "trigger_event":event,
                    "detected_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity":     "CRITICAL" if self.ip_counter.get_count(ip) > 20
                                    else "HIGH",
                })

        return alerts

    def get_stats(self) -> dict:
        """Return current window counts for all tracked keys."""
        return {
            "usernames": {
                k: self.user_counter.get_count(k)
                for k in self.user_counter._windows
            },
            "ips": {
                k: self.ip_counter.get_count(k)
                for k in self.ip_counter._windows
            },
        }
