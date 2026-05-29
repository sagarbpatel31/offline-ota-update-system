import unittest
from datetime import datetime

from ota.discovery import select_latest_compatible
from ota.policy import within_maintenance_window


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


if __name__ == "__main__":
    unittest.main()
