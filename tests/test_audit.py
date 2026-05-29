import unittest

from ota.release import find_attempt, summarize_attempts, summarize_policy_events, summarize_selection_events


class AuditTests(unittest.TestCase):
    def test_attempt_summary_marks_policy_rejection_terminal(self) -> None:
        history = [
            {"timestamp": "2026-01-01T00:00:00Z", "event": "verified", "version": "1.0.0"},
            {"timestamp": "2026-01-01T00:00:01Z", "event": "health_check_passed", "version": "1.0.0"},
            {
                "timestamp": "2026-01-01T00:01:00Z",
                "event": "policy_rejected",
                "version": "2.0.0",
                "error": "manual approval required",
            },
        ]

        attempts = summarize_attempts(history)
        self.assertEqual(attempts[0]["status"], "success")
        self.assertEqual(attempts[1]["status"], "policy_rejected")
        self.assertEqual(attempts[1]["finished_at"], "2026-01-01T00:01:00Z")

    def test_find_attempt_returns_timeline(self) -> None:
        history = [
            {"timestamp": "2026-01-01T00:00:00Z", "event": "verified", "version": "1.0.0"},
            {"timestamp": "2026-01-01T00:00:01Z", "event": "staged", "version": "1.0.0"},
            {"timestamp": "2026-01-01T00:00:02Z", "event": "health_check_passed", "version": "1.0.0"},
        ]
        attempts = summarize_attempts(history)
        attempt = find_attempt(attempts, attempts[0]["attempt_id"])
        self.assertIsNotNone(attempt)
        self.assertEqual(
            [event["event"] for event in attempt["timeline"]],
            ["verified", "staged", "health_check_passed"],
        )

    def test_policy_and_selection_summaries(self) -> None:
        history = [
            {"timestamp": "2026-01-01T00:00:00Z", "event": "selection_made", "version": "1.0.0", "source_type": "usb"},
            {"timestamp": "2026-01-01T00:00:01Z", "event": "selection_made", "version": "2.0.0", "source_type": "http"},
            {"timestamp": "2026-01-01T00:00:02Z", "event": "policy_rejected", "version": "3.0.0", "error": "mismatch"},
        ]
        policy = summarize_policy_events(history)
        selection = summarize_selection_events(history)
        self.assertEqual(policy["count"], 1)
        self.assertEqual(policy["by_reason"]["mismatch"], 1)
        self.assertEqual(selection["count"], 2)
        self.assertEqual(selection["by_source_type"]["usb"], 1)
        self.assertEqual(selection["by_source_type"]["http"], 1)


if __name__ == "__main__":
    unittest.main()
