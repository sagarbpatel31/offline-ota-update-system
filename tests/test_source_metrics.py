import unittest
from unittest.mock import patch

from server.main import policy_metrics, source_health_metrics


class SourceMetricsTests(unittest.TestCase):
    def test_policy_metrics_counts_selection_reasons(self) -> None:
        with patch("server.main.STATE_STORE.load") as mocked_load:
            mocked_load.return_value = {
                "discovered_bundles": [
                    {"selectable": True},
                    {"selectable": False, "selection_reason": "source is not trusted"},
                    {"selectable": False, "selection_reason": "retry cooldown active"},
                ],
                "source_health": {},
                "last_good_source_by_channel": {},
                "source_channel_stats": {},
            }
            payload = policy_metrics()
        self.assertEqual(payload["discovered_total"], 3)
        self.assertEqual(payload["selectable_total"], 1)
        self.assertEqual(payload["blocked_total"], 2)
        self.assertEqual(payload["selection_reasons"]["source is not trusted"], 1)

    def test_source_health_metrics_reports_quarantine_and_skip_reasons(self) -> None:
        with patch("server.main.STATE_STORE.load") as mocked_load:
            mocked_load.return_value = {
                "discovered_bundles": [],
                "source_events": [
                    {"timestamp": "2026-01-01T00:00:00+00:00", "source": "http://source-a.local", "event": "success"},
                    {"timestamp": "2026-01-01T00:01:00+00:00", "source": "http://source-b.local", "event": "failure"},
                    {"timestamp": "2026-01-01T00:02:00+00:00", "source": "http://source-b.local", "event": "skip"},
                ],
                "last_good_source_by_channel": {"stable": "http://source-a.local"},
                "source_channel_stats": {
                    "http://source-a.local": {"stable": {"successes": 3, "failures": 1}},
                    "http://source-b.local": {"stable": {"successes": 0, "failures": 2}},
                },
                "source_health": {
                    "http://source-a.local": {
                        "score": 40,
                        "reputation": 70,
                        "skip_reasons": {"source fetch backoff active": 2},
                        "backoff_until": "2099-01-01T00:10:00+00:00",
                    },
                    "http://source-b.local": {
                        "score": 10,
                        "reputation": 15,
                        "skip_reasons": {"source is quarantined": 1},
                        "quarantined_until": "2099-01-01T01:00:00+00:00",
                    },
                },
            }
            payload = source_health_metrics()
        self.assertEqual(payload["summary"]["total_sources"], 2)
        self.assertEqual(payload["summary"]["backoff_sources"], 1)
        self.assertEqual(payload["summary"]["quarantined_sources"], 1)
        self.assertEqual(payload["summary"]["skip_reasons"]["source fetch backoff active"], 2)
        self.assertEqual(payload["summary"]["event_counts"]["success"], 1)
        self.assertEqual(payload["summary"]["event_counts"]["failure"], 1)
        self.assertEqual(payload["summary"]["event_counts"]["skip"], 1)


if __name__ == "__main__":
    unittest.main()
