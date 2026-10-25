"""Unit test aturan evaluasi collector (heuristik dikunci kriteria canary)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import collector


def canary_event(**overrides):
    event = {
        "host_id": "server-a",
        "event_type": "file_modified",
        "path": "DEFNETT-LAB-CANARY.txt",
        "old_hash": None,
        "new_hash": "deadbeef",
        "content_signal": True,
        "indicator": "DEFNETT_LAB_CANARY",
    }
    event.update(overrides)
    return event


class TestCanaryDetection(unittest.TestCase):
    def test_full_canary_detected(self):
        self.assertTrue(collector.is_canary_detection(canary_event()))

    def test_missing_content_signal_not_canary(self):
        event = canary_event(content_signal=False)
        self.assertFalse(collector.is_canary_detection(event))

    def test_wrong_indicator_not_canary(self):
        self.assertFalse(collector.is_canary_detection(canary_event(indicator="OTHER")))

    def test_wrong_path_not_canary(self):
        self.assertFalse(collector.is_canary_detection(canary_event(path="index.txt")))

    def test_deleted_not_canary(self):
        self.assertFalse(collector.is_canary_detection(canary_event(event_type="file_deleted")))

    def test_missing_hash_not_canary(self):
        self.assertFalse(collector.is_canary_detection(canary_event(new_hash=None)))

    def test_unknown_host_not_canary(self):
        self.assertFalse(collector.is_canary_detection(canary_event(host_id="server-c")))

    def test_path_host_ok_positive(self):
        self.assertTrue(collector.canary_path_host_ok(canary_event()))

    def test_path_host_ok_missing_content(self):
        self.assertTrue(collector.canary_path_host_ok(canary_event(content_signal=False)))


class TestRiskScoring(unittest.TestCase):
    def test_canary_score(self):
        probability, risk, level, recommendation, verdict = collector.evaluate(canary_event())
        self.assertEqual((probability, level), (0.99, 3))
        self.assertEqual(recommendation, "auto_repair_canary_and_rejoin")
        self.assertEqual(verdict, "lab_canary_match")

    def test_file_created_low_risk(self):
        probability, risk, level, recommendation, verdict = collector.evaluate(
            canary_event(event_type="file_created", path="x", content_signal=False)
        )
        self.assertEqual(level, 0)
        self.assertEqual(recommendation, "record")
        self.assertEqual(verdict, "insufficient_evidence")

    def test_file_modified_operator_review(self):
        _, risk, level, recommendation, verdict = collector.evaluate(
            canary_event(event_type="file_modified", path="x", content_signal=False)
        )
        self.assertEqual(level, 2)
        self.assertEqual(recommendation, "operator_review")
        self.assertEqual(verdict, "suspicious")


if __name__ == "__main__":
    unittest.main()
