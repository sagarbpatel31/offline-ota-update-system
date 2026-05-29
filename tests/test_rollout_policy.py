import unittest

from ota.discovery import select_latest_compatible


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


if __name__ == "__main__":
    unittest.main()
