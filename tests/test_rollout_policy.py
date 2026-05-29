import unittest
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from ota.discovery import select_latest_compatible
from ota.policy import (
    adaptive_cooldown_minutes,
    adaptive_source_backoff_minutes,
    affinity_active,
    cooldown_active,
    decayed_channel_success_rate,
    poll_interval_active,
    resolve_source_policy,
    source_backoff_active,
    source_is_trusted,
    source_quarantined,
    within_maintenance_window,
)
from ota.release import ReleaseLayout, prune_old_releases


class RolloutPolicyTests(unittest.TestCase):
    def test_select_latest_compatible_prefers_selectable_highest_version(self) -> None:
        candidates = [
            {"version": "1.0.0", "selectable": True, "priority": 0, "channel": "stable", "source_type": "usb", "source": "a"},
            {"version": "2.0.0", "selectable": False, "priority": 100, "channel": "stable", "source_type": "http", "source": "b"},
            {"version": "1.5.0", "selectable": True, "priority": 1, "channel": "stable", "source_type": "http", "source": "c"},
        ]

        index, candidate = select_latest_compatible(candidates)
        self.assertEqual(index, 2)
        self.assertEqual(candidate["version"], "1.5.0")

    def test_select_latest_compatible_uses_priority_when_versions_match(self) -> None:
        candidates = [
            {"version": "2.0.0", "selectable": True, "priority": 1, "channel": "stable", "source_type": "usb", "source": "a"},
            {"version": "2.0.0", "selectable": True, "priority": 5, "channel": "stable", "source_type": "usb", "source": "b"},
        ]

        index, candidate = select_latest_compatible(candidates)
        self.assertEqual(index, 1)
        self.assertEqual(candidate["priority"], 5)

    def test_select_latest_compatible_uses_reputation_when_versions_and_priority_match(self) -> None:
        candidates = [
            {
                "version": "2.0.0",
                "selectable": True,
                "priority": 5,
                "source_reputation": 45,
                "source_score": 90,
                "channel": "stable",
                "source_type": "usb",
                "source": "a",
            },
            {
                "version": "2.0.0",
                "selectable": True,
                "priority": 5,
                "source_reputation": 80,
                "source_score": 60,
                "channel": "stable",
                "source_type": "usb",
                "source": "b",
            },
        ]

        index, candidate = select_latest_compatible(candidates)
        self.assertEqual(index, 1)
        self.assertEqual(candidate["source_reputation"], 80)

    def test_select_latest_compatible_prefers_last_good_source_when_equal(self) -> None:
        candidates = [
            {
                "version": "2.0.0",
                "selectable": True,
                "priority": 5,
                "preferred_source": False,
                "channel_success_rate": 95,
                "source_reputation": 80,
                "source_score": 80,
                "channel": "stable",
                "source_type": "http",
                "source": "http://a.local",
            },
            {
                "version": "2.0.0",
                "selectable": True,
                "priority": 5,
                "preferred_source": True,
                "channel_success_rate": 40,
                "source_reputation": 50,
                "source_score": 50,
                "channel": "stable",
                "source_type": "http",
                "source": "http://b.local",
            },
        ]

        index, candidate = select_latest_compatible(candidates)
        self.assertEqual(index, 1)
        self.assertTrue(candidate["preferred_source"])

    def test_select_latest_compatible_uses_channel_success_rate_after_affinity(self) -> None:
        candidates = [
            {
                "version": "2.0.0",
                "selectable": True,
                "priority": 5,
                "preferred_source": False,
                "channel_success_rate": 90,
                "source_reputation": 50,
                "source_score": 40,
                "channel": "stable",
                "source_type": "http",
                "source": "http://a.local",
            },
            {
                "version": "2.0.0",
                "selectable": True,
                "priority": 5,
                "preferred_source": False,
                "channel_success_rate": 20,
                "source_reputation": 90,
                "source_score": 90,
                "channel": "stable",
                "source_type": "http",
                "source": "http://b.local",
            },
        ]

        index, candidate = select_latest_compatible(candidates)
        self.assertEqual(index, 0)
        self.assertEqual(candidate["channel_success_rate"], 90)

    def test_select_latest_compatible_returns_none_when_no_selectable_candidates(self) -> None:
        self.assertIsNone(select_latest_compatible([{"version": "1.0.0", "selectable": False}]))

    def test_select_latest_compatible_uses_ring_after_version_and_priority(self) -> None:
        candidates = [
            {
                "version": "2.0.0",
                "selectable": True,
                "priority": 1,
                "ring": "general",
                "channel": "stable",
                "source_type": "usb",
                "source": "a",
            },
            {
                "version": "2.0.0",
                "selectable": True,
                "priority": 1,
                "ring": "canary-a",
                "channel": "stable",
                "source_type": "usb",
                "source": "b",
            },
        ]

        index, candidate = select_latest_compatible(candidates)
        self.assertEqual(index, 1)
        self.assertEqual(candidate["ring"], "canary-a")

    def test_within_maintenance_window_handles_same_day_window(self) -> None:
        self.assertTrue(
            within_maintenance_window(
                now=datetime(2026, 1, 1, 2, 30),
                window_start="01:00",
                window_end="05:00",
            )
        )
        self.assertFalse(
            within_maintenance_window(
                now=datetime(2026, 1, 1, 6, 0),
                window_start="01:00",
                window_end="05:00",
            )
        )

    def test_within_maintenance_window_handles_overnight_window(self) -> None:
        self.assertTrue(
            within_maintenance_window(
                now=datetime(2026, 1, 1, 23, 30),
                window_start="22:00",
                window_end="02:00",
            )
        )
        self.assertTrue(
            within_maintenance_window(
                now=datetime(2026, 1, 1, 1, 30),
                window_start="22:00",
                window_end="02:00",
            )
        )
        self.assertFalse(
            within_maintenance_window(
                now=datetime(2026, 1, 1, 12, 0),
                window_start="22:00",
                window_end="02:00",
            )
        )

    def test_source_is_trusted(self) -> None:
        self.assertTrue(source_is_trusted("http://trusted.local/update", trusted_sources=["http://trusted.local"]))
        self.assertFalse(source_is_trusted("http://evil.local/update", trusted_sources=["http://trusted.local"]))

    def test_cooldown_active(self) -> None:
        self.assertTrue(
            cooldown_active(
                version="1.0.0",
                failed_versions={"1.0.0": "2026-01-01T00:00:00+00:00"},
                cooldown_minutes=30,
                now=datetime(2026, 1, 1, 0, 10),
            )
        )

    def test_adaptive_cooldown_minutes_scales_and_caps(self) -> None:
        self.assertEqual(adaptive_cooldown_minutes(base_minutes=30, failure_count=1), 30)
        self.assertEqual(adaptive_cooldown_minutes(base_minutes=30, failure_count=2), 60)
        self.assertEqual(adaptive_cooldown_minutes(base_minutes=30, failure_count=3), 120)
        self.assertEqual(adaptive_cooldown_minutes(base_minutes=60, failure_count=10), 24 * 60)
        self.assertFalse(
            cooldown_active(
                version="1.0.0",
                failed_versions={"1.0.0": "2026-01-01T00:00:00+00:00"},
                cooldown_minutes=30,
                now=datetime(2026, 1, 1, 1, 0),
            )
        )

    def test_adaptive_source_backoff_minutes_scales_and_caps(self) -> None:
        self.assertEqual(adaptive_source_backoff_minutes(base_minutes=5, consecutive_failures=1), 5)
        self.assertEqual(adaptive_source_backoff_minutes(base_minutes=5, consecutive_failures=2), 10)
        self.assertEqual(adaptive_source_backoff_minutes(base_minutes=5, consecutive_failures=3), 20)
        self.assertEqual(adaptive_source_backoff_minutes(base_minutes=120, consecutive_failures=10), 12 * 60)

    def test_source_backoff_active(self) -> None:
        self.assertTrue(
            source_backoff_active(
                {"backoff_until": "2026-01-01T00:10:00+00:00"},
                now=datetime(2026, 1, 1, 0, 5),
            )
        )
        self.assertFalse(
            source_backoff_active(
                {"backoff_until": "2026-01-01T00:10:00+00:00"},
                now=datetime(2026, 1, 1, 0, 15),
            )
        )

    def test_source_quarantined(self) -> None:
        self.assertTrue(
            source_quarantined(
                {"quarantined_until": "2026-01-01T02:00:00+00:00"},
                now=datetime(2026, 1, 1, 1, 30),
            )
        )
        self.assertFalse(
            source_quarantined(
                {"quarantined_until": "2026-01-01T02:00:00+00:00"},
                now=datetime(2026, 1, 1, 2, 30),
            )
        )

    def test_resolve_source_policy_prefers_longest_prefix(self) -> None:
        policy = resolve_source_policy(
            "http://updates.local/team-a/device",
            {
                "http://updates.local/": {"priority_override": 2},
                "http://updates.local/team-a/": {"priority_override": 8},
            },
        )
        self.assertEqual(policy["priority_override"], 8)

    def test_poll_interval_active(self) -> None:
        self.assertTrue(
            poll_interval_active(
                last_attempted_at="2026-01-01T00:00:00+00:00",
                poll_interval_minutes=15,
                now=datetime(2026, 1, 1, 0, 10),
            )
        )
        self.assertFalse(
            poll_interval_active(
                last_attempted_at="2026-01-01T00:00:00+00:00",
                poll_interval_minutes=15,
                now=datetime(2026, 1, 1, 0, 20),
            )
        )

    def test_affinity_active(self) -> None:
        self.assertTrue(
            affinity_active(
                last_success_at="2026-01-01T00:00:00+00:00",
                ttl_hours=72,
                now=datetime(2026, 1, 2, 0, 0),
            )
        )
        self.assertFalse(
            affinity_active(
                last_success_at="2026-01-01T00:00:00+00:00",
                ttl_hours=24,
                now=datetime(2026, 1, 3, 0, 1),
            )
        )

    def test_decayed_channel_success_rate_penalizes_recent_failures(self) -> None:
        self.assertEqual(
            decayed_channel_success_rate(
                successes=8,
                failures=3,
                last_failure_at="2026-01-01T12:00:00+00:00",
                decay_threshold=3,
                decay_penalty=20,
                now=datetime(2026, 1, 2, 0, 0),
            ),
            52,
        )
        self.assertEqual(
            decayed_channel_success_rate(
                successes=8,
                failures=2,
                last_failure_at="2026-01-01T12:00:00+00:00",
                decay_threshold=3,
                decay_penalty=20,
                now=datetime(2026, 1, 2, 0, 0),
            ),
            80,
        )

    def test_prune_old_releases_keeps_active_previous_and_limit(self) -> None:
        with TemporaryDirectory() as tmpdir:
            layout = ReleaseLayout(Path(tmpdir))
            layout.ensure()
            for version in ["1.0.0", "1.1.0", "1.2.0", "1.3.0"]:
                layout.release_dir(version).mkdir(parents=True, exist_ok=True)
            layout.active_link.symlink_to(layout.release_dir("1.3.0"))
            layout.previous_version_file.write_text("1.2.0\n")
            removed = prune_old_releases(layout, keep=1)
            self.assertIn("1.0.0", removed)
            self.assertNotIn("1.3.0", removed)
            self.assertNotIn("1.2.0", removed)


if __name__ == "__main__":
    unittest.main()
