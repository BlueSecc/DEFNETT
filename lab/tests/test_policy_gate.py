"""Unit test Policy Gate deterministik."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if os.environ.get("POLICY_ADVISORY_HOLD"):
    del os.environ["POLICY_ADVISORY_HOLD"]

import policy


def base_context(**overrides):
    context = {
        "event": {
            "host_id": "server-a",
            "event_type": "file_modified",
            "path": "DEFNETT-LAB-CANARY.txt",
            "old_hash": None,
            "new_hash": "abc",
            "content_signal": True,
            "indicator": "DEFNETT_LAB_CANARY",
        },
        "evidence_valid": True,
        "risk": 1.98,
        "level": 3,
        "target": "server-a",
        "survivor": "server-b",
        "target_allowed": True,
        "backend_states": {"server-a": "UP", "server-b": "UP"},
        "survivor_reachable": True,
        "active_drains": [],
        "last_action_seconds_ago": None,
        "recent_action_count": 0,
        "canary_run_in_progress": False,
        "evidence_ids": ["event-1"],
        "advisor_status": "disabled",
        "advisor_verdict": None,
    }
    context.update(overrides)
    return context


def context_with_event_field(field, value, **overrides):
    context = base_context(**overrides)
    context["event"] = dict(context["event"], **{field: value})
    return context


class TestPolicyGate(unittest.TestCase):
    def setUp(self):
        self.config = policy.PolicyConfig({"POLICY_MIN_RISK": "1.0"})

    def test_full_context_approved(self):
        decision = policy.evaluate_containment(base_context(), self.config)
        self.assertEqual(decision["decision"], policy.DECISION_APPROVED)
        self.assertEqual(decision["config"]["name"], policy.CONFIG_VERSION)
        self.assertEqual(decision["failed_codes"], [])
        self.assertTrue(all(item["passed"] for item in decision["reasons"]))

    def test_invalid_evidence_rejected(self):
        context = context_with_event_field("content_signal", False, evidence_valid=False)
        decision = policy.evaluate_containment(context, self.config)
        self.assertEqual(decision["decision"], policy.DECISION_REJECTED)
        self.assertIn("EVIDENCE_INSUFFICIENT", decision["failed_codes"])

    def test_target_not_allowed(self):
        decision = policy.evaluate_containment(
            base_context(target="server-c", target_allowed=False),
            self.config,
        )
        self.assertIn("TARGET_NOT_ALLOWED", decision["failed_codes"])

    def test_risk_below_threshold_rejected(self):
        decision = policy.evaluate_containment(base_context(risk=0.7), self.config)
        self.assertIn("RISK_BELOW_THRESHOLD", decision["failed_codes"])

    def test_survivor_down_rejected(self):
        context = base_context(
            backend_states={"server-a": "UP", "server-b": "DOWN"},
            survivor_reachable=False,
        )
        decision = policy.evaluate_containment(context, self.config)
        self.assertIn("SURVIVOR_NOT_HEALTHY", decision["failed_codes"])

    def test_capacity_probe_required_rejected(self):
        config = policy.PolicyConfig({"POLICY_CAPACITY_PROBE_REQUIRED": "true"})
        decision = policy.evaluate_containment(base_context(survivor_reachable=None), config)
        self.assertIn("SURVIVOR_CAPACITY_UNVERIFIED", decision["failed_codes"])

    def test_capacity_probe_failed_rejected(self):
        decision = policy.evaluate_containment(base_context(survivor_reachable=False), self.config)
        self.assertIn("SURVIVOR_CAPACITY_FAILED", decision["failed_codes"])

    def test_target_state_unknown_fail_safe(self):
        decision = policy.evaluate_containment(
            base_context(backend_states={"server-a": None, "server-b": "UP"}),
            self.config,
        )
        self.assertIn("TARGET_STATE_UNKNOWN", decision["failed_codes"])
        self.assertEqual(decision["decision"], policy.DECISION_REJECTED)

    def test_drain_limit_reached(self):
        context = base_context(active_drains=["server-b"])
        decision = policy.evaluate_containment(context, self.config)
        self.assertIn("DRAIN_LIMIT_REACHED", decision["failed_codes"])
        self.assertEqual(decision["decision"], policy.DECISION_REJECTED)

    def test_action_in_progress_rejected(self):
        decision = policy.evaluate_containment(base_context(canary_run_in_progress=True), self.config)
        self.assertIn("ACTION_IN_PROGRESS", decision["failed_codes"])

    def test_cooldown_active_rejected(self):
        decision = policy.evaluate_containment(base_context(last_action_seconds_ago=5), self.config)
        self.assertIn("COOLDOWN_ACTIVE", decision["failed_codes"])

    def test_rate_limit_reached(self):
        config = policy.PolicyConfig({"POLICY_RATE_MAX_ACTIONS": "2"})
        decision = policy.evaluate_containment(base_context(recent_action_count=2), config)
        self.assertIn("RATE_LIMIT_REACHED", decision["failed_codes"])

    def test_advisor_hold(self):
        context = base_context(
            advisor_status="completed",
            advisor_verdict="benign",
        )
        decision = policy.evaluate_containment(context, self.config)
        self.assertEqual(decision["decision"], policy.DECISION_HELD)
        self.assertIn("ADVISOR_HOLD", decision["failed_codes"])

    def test_advisor_hold_rejected_when_disabled(self):
        decision = policy.evaluate_containment(
            base_context(advisor_status="completed", advisor_verdict="benign"),
            self.config,
        )
        self.assertEqual(decision["decision"], policy.DECISION_HELD)
        self.assertIn("ADVISOR_HOLD", decision["failed_codes"])

    def test_advisor_output_invalid_failsafe(self):
        context = base_context(advisor_status="unavailable", advisor_verdict="benign")
        decision = policy.evaluate_containment(context, self.config)
        self.assertIn("ADVISOR_OUTPUT_INVALID", decision["failed_codes"])

    def test_advisor_suspicious_no_hold(self):
        decision = policy.evaluate_containment(
            base_context(advisor_status="completed", advisor_verdict="suspicious"),
            self.config,
        )
        self.assertIn("ADVISOR_NO_HOLD", [reason["code"] for reason in decision["reasons"]])
        self.assertEqual(decision["decision"], policy.DECISION_APPROVED)

    def test_unknown_survivor_state_is_fail_safe(self):
        context = base_context(backend_states={"server-a": "UP", "server-b": "N/A"})
        decision = policy.evaluate_containment(context, self.config)
        self.assertIn("SURVIVOR_STATE_UNKNOWN", decision["failed_codes"])
        self.assertEqual(decision["decision"], policy.DECISION_REJECTED)

    def test_config_snapshot_contains_limits(self):
        config = policy.PolicyConfig({"POLICY_COOLDOWN_SECONDS": "20"})
        snapshot = config.snapshot()
        self.assertEqual(snapshot["cooldown_seconds"], 20)
        self.assertEqual(snapshot["max_drained_backends"], 1)


if __name__ == "__main__":
    unittest.main()
